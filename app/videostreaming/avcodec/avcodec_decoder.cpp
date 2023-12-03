#include "avcodec_decoder.h"
#include "qdebug.h"
#include <QFileInfo>
#include <iostream>
#include <sstream>

#include "avcodec_helper.hpp"
#include "../common/TimeHelper.hpp"
#include "common/util_fs.h"

#include "texturerenderer.h"
#include "decodingstatistcs.h"
#include "common/SchedulingHelper.hpp"
#include "../util/WorkaroundMessageBox.h"
#include "../logging/hudlogmessagesmodel.h"
#include "../logging/logmessagesmodel.h"

#include "ExternalDecodeService.hpp"

static int hw_decoder_init(AVCodecContext *ctx, const enum AVHWDeviceType type){
    int err = 0;
    ctx->hw_frames_ctx = NULL;
    // ctx->hw_device_ctx gets freed when we call avcodec_free_context
    if ((err = av_hwdevice_ctx_create(&ctx->hw_device_ctx, type,
                                      /*"auto"*/ NULL , NULL, 0)) < 0) {
        fprintf(stderr, "Failed to create specified HW device.\n");
        return err;
    }
    return err;
}

static enum AVPixelFormat wanted_hw_pix_fmt;
static enum AVPixelFormat get_hw_format(AVCodecContext *ctx,const enum AVPixelFormat *pix_fmts){
    const enum AVPixelFormat *p;
    AVPixelFormat ret=AV_PIX_FMT_NONE;
    std::stringstream supported_formats;
    for (p = pix_fmts; *p != -1; p++) {
        const int tmp=(int)*p;
        supported_formats<<safe_av_get_pix_fmt_name(*p)<<"("<<tmp<<"),";
        if (*p == wanted_hw_pix_fmt){
          // matches what we want
          ret=*p;
        }
    }
    qDebug()<<"Supported (HW) pixel formats: "<<supported_formats.str().c_str();
    if(ret==AV_PIX_FMT_NONE){
      fprintf(stderr, "Failed to get HW surface format. Wanted: %s\n", av_get_pix_fmt_name(wanted_hw_pix_fmt));
    }
        
    return ret;
}

typedef struct DecodeContext {
    AVBufferRef *hw_device_ref;
} DecodeContext;

// https://ffmpeg.org/doxygen/trunk/doc_2examples_2qsvdec_8c_source.html
static enum AVPixelFormat  get_qsv_format(AVCodecContext *avctx, const enum AVPixelFormat *pix_fmts){
    while (*pix_fmts != AV_PIX_FMT_NONE) {
        if (*pix_fmts == AV_PIX_FMT_QSV) {
            return AV_PIX_FMT_QSV;
            //return AV_PIX_FMT_NV12;
            //return AV_PIX_FMT_VAAPI;AV_PIX_FMT_NV12
        }
        pix_fmts++;
    }
    fprintf(stderr, "The QSV pixel format not offered in get_format()\n");
    return AV_PIX_FMT_NONE;

}




// For SW decode, we support YUV420 | YUV422 and their (mjpeg) abbreviates since
// we can always copy and render these formats via OpenGL - and when we are doing SW decode
// we most likely are on a (fast) x86 platform where we can copy those formats via CPU
// relatively easily, at least the resolutions common in OpenHD
static enum AVPixelFormat get_sw_format(AVCodecContext *ctx,const enum AVPixelFormat *pix_fmts){
    const enum AVPixelFormat *p;
    qDebug()<<"All (SW) pixel formats:"<<all_formats_to_string(pix_fmts).c_str();
    for (p = pix_fmts; *p != -1; p++) {
        const AVPixelFormat tmp=*p;
        if(tmp==AV_PIX_FMT_YUV420P || tmp==AV_PIX_FMT_YUV422P || tmp==AV_PIX_FMT_YUVJ422P || tmp==AV_PIX_FMT_YUVJ420P){
            return tmp;
        }
    }
    qDebug()<<"Weird, we should be able to do SW decoding on all platforms";
    return AV_PIX_FMT_NONE;
}


AVCodecDecoder::AVCodecDecoder(QObject *parent):
    QObject(parent)
{
    //drm_prime_out=std::make_unique<DRMPrimeOut>(1,false,false);
}

AVCodecDecoder::~AVCodecDecoder()
{
    terminate();
}

void AVCodecDecoder::init(bool primaryStream)
{
    qDebug() << "AVCodecDecoder::init()";
    m_last_video_settings=QOpenHDVideoHelper::read_config_from_settings();
    decode_thread = std::make_unique<std::thread>([this]{this->constant_decode();} );
    timer_check_settings_changed=std::make_unique<QTimer>();
    QObject::connect(timer_check_settings_changed.get(), &QTimer::timeout, this, &AVCodecDecoder::timer_check_settings_changed_callback);
    timer_check_settings_changed->start(1000);
}

void AVCodecDecoder::terminate()
{
    // Stop the timer, which can be done (almost) immediately (it's runnable doesn't block)
    timer_check_settings_changed->stop();
    timer_check_settings_changed=nullptr;
    // This will stop the constant_decode as soon as the current running decode_until_error loop returns
    m_should_terminate=true;
    // This will break out of a running "decode until error" loop if there is one currently running
    request_restart=true;
    if(decode_thread){
        // Wait for everything to cleanup and stop
        decode_thread->join();
    }
}

void AVCodecDecoder::timer_check_settings_changed_callback()
{
    const auto new_settings=QOpenHDVideoHelper::read_config_from_settings();
    if(m_last_video_settings!=new_settings){
        // We just request a restart from the video (break out of the current constant_decode() loop,
        // and restart with the new settings.
        request_restart=true;
        m_last_video_settings=new_settings;
    }
}

void AVCodecDecoder::constant_decode()
{
    while(!m_should_terminate){
        qDebug()<<"Start decode";
        const auto settings = QOpenHDVideoHelper::read_config_from_settings();
        // this is always for primary video, unless switching is enabled
        auto stream_config=settings.primary_stream_config;
        if(settings.generic.qopenhd_switch_primary_secondary){
            stream_config=settings.secondary_stream_config;
        }
         bool do_custom_rtp=settings.generic.dev_use_low_latency_parser_when_possible;
         if(stream_config.video_codec==QOpenHDVideoHelper::VideoCodecMJPEG){
             // we got no support for mjpeg in our custom rtp parser
             do_custom_rtp=false;
        }
        // On a couple of embedded platform(s) we do not do the decoding in qopenhd,
        // but by using a "decode service" that renders / composes the video into a plane behind qopenhd
        // on rpi, this is by far the most performant / low latency option
        bool use_external_decode_service=false;
        // choice - enable regardless of platform, usefull for development
        if(settings.generic.dev_always_use_generic_external_decode_service){
            use_external_decode_service=true;
        }
        bool is_rpi=false;
#ifdef IS_PLATFORM_RPI
        is_rpi=true;
#endif // IS_PLATFORM_RPI
        if(is_rpi && settings.generic.dev_rpi_use_external_omx_decode_service){
            use_external_decode_service=true;
        }
        if(use_external_decode_service){
            dirty_generic_decode_via_external_decode_service(settings);
        }else{
            if(settings.generic.dev_test_video_mode!=QOpenHDVideoHelper::VideoTestMode::DISABLED){
                // file playback always goes via non-custom rtp parser (since it is not rtp)
                do_custom_rtp=false;
            }
            do_custom_rtp=true;
            if(do_custom_rtp){
                // Does h264 and h265 custom rtp parse, but uses avcodec for decode
                open_and_decode_until_error_custom_rtp(settings);
            }else{
                open_and_decode_until_error(settings);
            }
        }
        qDebug()<<"Decode stopped,restarting";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}


int AVCodecDecoder::decode_and_wait_for_frame(AVPacket *packet,std::optional<std::chrono::steady_clock::time_point> parse_time)
{
    AVFrame *frame = nullptr;
    //qDebug()<<"Decode packet:"<<packet->pos<<" size:"<<packet->size<<" B";
    const auto beforeFeedFrame=std::chrono::steady_clock::now();
    if(parse_time!=std::nullopt){
        const auto delay=beforeFeedFrame-parse_time.value();
        avg_parse_time.add(delay);
        avg_parse_time.custom_print_in_intervals(std::chrono::seconds(3),[](const std::string name,const std::string message){
            //qDebug()<<name.c_str()<<":"<<message.c_str();
            DecodingStatistcs::instance().set_parse_and_enqueue_time(message.c_str());
        });
    }
    const auto beforeFeedFrameUs=getTimeUs();
    packet->pts=beforeFeedFrameUs;
    timestamp_add_fed(packet->pts);

    //m_ffmpeg_dequeue_or_queue_mutex.lock();
    const int ret_avcodec_send_packet = avcodec_send_packet(decoder_ctx, packet);
    //m_ffmpeg_dequeue_or_queue_mutex.unlock();
    if (ret_avcodec_send_packet < 0) {
       // fprintf(stderr, "Error during decoding\n");
        char errbuf[AV_ERROR_MAX_STRING_SIZE] = {0};
        av_strerror(ret_avcodec_send_packet, errbuf, AV_ERROR_MAX_STRING_SIZE);
        fprintf(stderr, "Error during decoding: %s\n",  errbuf);

        return ret_avcodec_send_packet;
    }
    // alloc output frame(s)
    if (!(frame = av_frame_alloc())) {
        // NOTE: It is a common practice to not care about OOM, and this is the best approach in my opinion.
        // but ffmpeg uses malloc and returns error codes, so we keep this practice here.
        qDebug()<<"can not alloc frame";
        av_frame_free(&frame);
        return AVERROR(ENOMEM);
    }
    int ret=0;
    // Poll until we get the frame out
    const auto loopUntilFrameBegin=std::chrono::steady_clock::now();
    bool gotFrame=false;
    int n_times_we_tried_getting_a_frame_this_time=0;
    while (!gotFrame){
        //m_ffmpeg_dequeue_or_queue_mutex.lock();
        ret = avcodec_receive_frame(decoder_ctx, frame);
        //m_ffmpeg_dequeue_or_queue_mutex.unlock();
        if(ret == AVERROR_EOF){
            qDebug()<<"Got EOF";
            break;
        }else if(ret==0){
            //debug_is_valid_timestamp(frame->pts);
            // we got a new frame
            if(!use_frame_timestamps_for_latency){
                const auto x_delay=std::chrono::steady_clock::now()-beforeFeedFrame;
                //qDebug()<<"(True) decode delay(wait):"<<((float)std::chrono::duration_cast<std::chrono::microseconds>(x_delay).count()/1000.0f)<<" ms";
                avg_decode_time.add(x_delay);
            }else{
                const auto now_us=getTimeUs();
                const auto delay_us=now_us-frame->pts;
                //qDebug()<<"(True) decode delay(nowait):"<<((float)delay_us/1000.0f)<<" ms";
                //MLOGD<<"Frame pts:"<<frame->pts<<" Set to:"<<now<<"\n";
                //frame->pts=now;
                avg_decode_time.add(std::chrono::microseconds(delay_us));
            }
            gotFrame=true;
            frame->pts=beforeFeedFrameUs;
            // display frame
            on_new_frame(frame);
            avg_decode_time.custom_print_in_intervals(std::chrono::seconds(3),[](const std::string name,const std::string message){
                qDebug()<<name.c_str()<<":"<<message.c_str();
                DecodingStatistcs::instance().set_decode_time(message.c_str());
            });
        }else if(ret==AVERROR(EAGAIN)){
            // TODO FIXME REMOVE
            if(true){
                break;
            }
            if(n_no_output_frame_after_x_seconds>=2){
                // note decode latency is now wrong
                //qDebug()<<"Skipping decode lockstep due to no frame for more than X seconds\n";
                DecodingStatistcs::instance().set_doing_wait_for_frame_decode("No");
                if(n_times_we_tried_getting_a_frame_this_time>4){
                    break;
                }
            }
            //std::cout<<"avcodec_receive_frame returned:"<<ret<<"\n";
            // for some video files, the decoder does not output a frame every time a h264 frame has been fed
            // In this case, I unblock after X seconds, but we cannot measure the decode delay by using the before-after
            // approach. We can still measure it using the pts timestamp from av, but this one cannot necessarily be trusted 100%
            if(std::chrono::steady_clock::now()-loopUntilFrameBegin > std::chrono::seconds(2)){
              qDebug()<<"Got no frame after X seconds. Break, but decode delay will be reported wrong";
              n_no_output_frame_after_x_seconds++;
              use_frame_timestamps_for_latency=true;
              break;
            }
            // sleep a bit to not hog the CPU too much
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }else{
            qDebug()<<"Got unlikely / weird error:"<<ret;
            break;
        }
        n_times_we_tried_getting_a_frame_this_time++;
    }
    av_frame_free(&frame);
    return 0;
}

int AVCodecDecoder::decode_config_data(AVPacket *packet)
{
     const int ret_avcodec_send_packet = avcodec_send_packet(decoder_ctx, packet);
     return ret_avcodec_send_packet;
}


bool AVCodecDecoder::feed_rtp_frame_if_available()
{
    auto frame=m_rtp_receiver->get_next_frame();
    if(frame){
        {
            // parsing delay
            const auto delay=std::chrono::steady_clock::now()-frame->get_nal().creationTime;
            avg_parse_time.add(delay);
            avg_parse_time.custom_print_in_intervals(std::chrono::seconds(3),[](const std::string name,const std::string message){
                //qDebug()<<name.c_str()<<":"<<message.c_str();
                DecodingStatistcs::instance().set_parse_and_enqueue_time(message.c_str());
            });
        }
        AVPacket *pkt=av_packet_alloc();
        pkt->data=(uint8_t*)frame->get_nal().getData();
        pkt->size=frame->get_nal().getSize();
        const auto beforeFeedFrameUs=getTimeUs();
        pkt->pts=beforeFeedFrameUs;
        timestamp_add_fed(pkt->pts);
        avcodec_send_packet(decoder_ctx, pkt);
        av_packet_free(&pkt);
        return true;
    }
    return false;
}

void AVCodecDecoder::fetch_frame_or_feed_input_packet(){
    AVPacket *pkt=av_packet_alloc();
    bool keep_fetching_frames_or_input_packets=true;
    while(keep_fetching_frames_or_input_packets){
        if(request_restart){
            keep_fetching_frames_or_input_packets=false;
            request_restart=false;
            continue;
        }
        AVFrame* frame= av_frame_alloc();
        assert(frame);
        const int ret = avcodec_receive_frame(decoder_ctx, frame);
        //m_ffmpeg_dequeue_or_queue_mutex.unlock();
        if(ret == AVERROR_EOF){
            qDebug()<<"Got EOF";
            keep_fetching_frames_or_input_packets=false;
        }else if(ret==0){
            timestamp_debug_valid(frame->pts);
            // we got a new frame
            const auto now_us=getTimeUs();
            const auto delay_us=now_us-frame->pts;
            //qDebug()<<"(True) decode delay(nowait):"<<((float)delay_us/1000.0f)<<" ms";
            //frame->pts=now;
            avg_decode_time.add(std::chrono::microseconds(delay_us));
            // display frame
            on_new_frame(frame);
            avg_decode_time.custom_print_in_intervals(std::chrono::seconds(3),[](const std::string name,const std::string message){
                 //qDebug()<<name.c_str()<<":"<<message.c_str();
                 DecodingStatistcs::instance().set_decode_time(message.c_str());
            });
            av_frame_free(&frame);
            frame= av_frame_alloc();
        }else if(ret==AVERROR(EAGAIN)){
            //qDebug()<<"Needs more data";
            // Get more encoded data
            const bool success=feed_rtp_frame_if_available();
            if(!success){
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }else{
            qDebug()<<"Weird decoder error:"<<ret;
            keep_fetching_frames_or_input_packets=false;
        }
    }
    av_packet_free(&pkt);
}

void AVCodecDecoder::on_new_frame(AVFrame *frame)
{
    {
        std::stringstream ss;
        ss<<safe_av_get_pix_fmt_name((AVPixelFormat)frame->format)<<" "<<frame->width<<"x"<<frame->height;
        DecodingStatistcs::instance().set_primary_stream_frame_format(QString(ss.str().c_str()));
        //qDebug()<<"Got frame:"<<ss.str().c_str();
    }
    // Once we got the first frame, reduce the log level
    av_log_set_level(AV_LOG_WARNING);
    //qDebug()<<debug_frame(frame).c_str();
    TextureRenderer::instance().queue_new_frame_for_display(frame);
    if(last_frame_width==-1 || last_frame_height==-1){
        last_frame_width=frame->width;
        last_frame_height=frame->height;
    }else{
        if(last_frame_width!=frame->width || last_frame_height!=frame->height){
            // PI and SW decoer will just slently start outputting garbage frames
            // if the width/ height changes during RTP streaming
            qDebug()<<"Need to restart the decoder, width / heght changed";
            request_restart=true;
        }
    }
    //drm_prime_out->queue_new_frame_for_display(frame);
}

void AVCodecDecoder::reset_before_decode_start()
{
    n_no_output_frame_after_x_seconds=0;
    last_frame_width=-1;
    last_frame_height=-1;
    avg_decode_time.reset();
    avg_parse_time.reset();
    DecodingStatistcs::instance().reset_all_to_default();
    last_frame_width=-1;
    last_frame_height=-1;
    m_fed_timestamps_queue.clear();
}



void print_codec_parameters(AVCodecParameters *params) {
    //AVClass *av_class = avcodec_parameters_get_class();
    const AVOption *option = NULL;

}


void printHex(const uint8_t *data, size_t size) {
    char* hexString = (char*)malloc((size * 2 + 1) * sizeof(char)); // Each byte represented by 2 characters, plus a null terminator
    if (hexString == NULL) {
        return ; // Memory allocation failed
    }
    for (size_t i = 0; i < size; ++i) {
        sprintf(hexString + i * 2, "%02X", data[i]); // Convert each byte to a 2-digit hex value and store in the string
    }
    hexString[size * 2] = '\0'; // Null terminator to mark the end of the string
    qDebug()<<hexString;
    free(hexString);
}

void saveBufferToFile(const char *filename, uint8_t *buffer, size_t size) {
    FILE *file = fopen(filename, "wb"); // Open file for writing in binary mode, overwrites existing file
    if (file == NULL) {
        perror("Error opening file");
        return;
    }
    size_t bytes_written = fwrite(buffer, sizeof(uint8_t), size, file);
    if (bytes_written != size) {
        perror("Error writing to file");
    }

    fclose(file);
}

void saveBufferToFileAppend(const char *filename, uint8_t *buffer, size_t size) {
    FILE *file = fopen(filename, "ab"); // Open file for writing in binary mode, append
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    size_t bytes_written = fwrite(buffer, sizeof(uint8_t), size, file);
    if (bytes_written != size) {
        perror("Error writing to file");
    }

    fclose(file);
}

uint8_t* readFileToBuffer(const char *filename, int *size) {
    FILE *file = fopen(filename, "rb"); // Open file for reading in binary mode
    if (file == NULL) {
        perror("Error opening file");
        return NULL;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for buffer
    uint8_t *buffer = (uint8_t *)malloc(file_size + AV_INPUT_BUFFER_PADDING_SIZE );
    if (buffer == NULL) {
        fclose(file);
        perror("Memory allocation failed");
        return NULL;
    }

    // Read file contents into buffer
    size_t bytes_read = fread(buffer, sizeof(uint8_t), file_size, file);
    if (bytes_read != file_size) {
        fclose(file);
        free(buffer);
        perror("Error reading file");
        return NULL;
    }

    fclose(file);

    // Set the size of the buffer if size pointer is provided
    if (size != NULL) {
        *size = (int)file_size;
    }

    return buffer;
}

int AVCodecDecoder::open_and_decode_until_error(const QOpenHDVideoHelper::VideoStreamConfig settings)
{
    // this is always for primary video, unless switching is enabled
    auto stream_config=settings.primary_stream_config;
    if(settings.generic.qopenhd_switch_primary_secondary){
        stream_config=settings.secondary_stream_config;
    }
    std::string in_filename="";
    if(false /*settings.generic.dev_test_video_mode==QOpenHDVideoHelper::VideoTestMode::DISABLED*/){
        in_filename=QOpenHDVideoHelper::get_udp_rtp_sdp_filename(stream_config);
        //in_filename="rtp://192.168.0.1:5600";
    }else{
        if(settings.generic.dev_enable_custom_pipeline){
            in_filename=settings.generic.dev_custom_pipeline;
        }else{
            // For testing, I regulary change the filename(s) and recompile
            const bool consti_testing=true;
            if(consti_testing){
                if(stream_config.video_codec==QOpenHDVideoHelper::VideoCodecH264){
                     //in_filename="/tmp/x_raw_h264.h264";
                    in_filename="/home/consti10/Desktop/hello_drmprime/in/rpi_1080.h264";
                    //in_filename="/home/consti10/Desktop/hello_drmprime/in/rv_1280x720_green_white.h264";
                    //in_filename="/home/consti10/Desktop/hello_drmprime/in/Big_Buck_Bunny_1080_10s_1MB_h264.mp4";
                }else if(stream_config.video_codec==QOpenHDVideoHelper::VideoCodecH265){
                      //in_filename="/tmp/x_raw_h265.h265";
                    in_filename="/home/consti10/Desktop/hello_drmprime/in/jetson_test.h265";
                    in_filename="/home/home/Videos/h265f60.mov";
                    in_filename="/home/home/Videos/h265f60a.h265";//annexb
                    //in_filename="/home/home/Videos/sample1080.hevc";

                    //in_filename="/home/consti10/Desktop/hello_drmprime/in/Big_Buck_Bunny_1080_10s_1MB_h265.mp4";
                }else{
                   in_filename="/home/consti10/Desktop/hello_drmprime/in/uv_640x480.mjpeg";
                   //in_filename="/home/consti10/Desktop/hello_drmprime/in/Big_Buck_Bunny_1080.mjpeg";
                }
            }else{
                in_filename=QOpenHDVideoHelper::get_default_openhd_test_file(stream_config.video_codec);
            }

        }
    }
    av_log_set_level(AV_LOG_TRACE);

    // These options are needed for using the foo.sdp (rtp streaming)
    // https://stackoverflow.com/questions/20538698/minimum-sdp-for-making-a-h264-rtp-stream
    // https://stackoverflow.com/questions/16658873/how-to-minimize-the-delay-in-a-live-streaming-with-ffmpeg
    AVDictionary* av_dictionary=nullptr;
    av_dict_set(&av_dictionary, "protocol_whitelist", "file,udp,rtp", 0);
    /*av_dict_set(&av_dictionary, "buffer_size", "212992", 0);
    av_dict_set_int(&av_dictionary,"max_delay",0,0);
    av_dict_set(&av_dictionary,"reuse_sockets","1",0);
    av_dict_set_int(av_dictionary, "reorder_queue_size", 0, 0);
    av_dict_set_int(&av_dictionary,"network-caching",0,0);
    //
    //av_dict_set(&av_dictionary,"sync","ext",0);
    //
    //av_dict_set_int(&av_dictionary, "probesize", 32, 0);
    //av_dict_set_int(&av_dictionary, "analyzeduration", 1000*100, 0); // Is in microseconds

    // I think those values are in seconds ?
    av_dict_set_int(&av_dictionary, "rw_timeout", 1000*100, 0); //microseconds
    av_dict_set_int(&av_dictionary, "stimeout", 1000*100, 0); //microseconds
    //av_dict_set_int(&av_dictionary, "rw_timeout", 0, 0);
    //av_dict_set_int(&av_dictionary, "stimeout",0, 0);
    av_dict_set_int(&av_dictionary,"rtbufsize",0,0);
    av_dict_set_int(&av_dictionary,"max_interleave_delta",1,0); //in microseconds
    //av_dict_set_int(&av_dictionary,"max_streams",1,0);

    av_dict_set(&av_dictionary, "rtsp_transport", "udp", 0);*/

    av_dict_set(&av_dictionary,"timeout",0,0);

    // For decode ?!
    av_dict_set_int(&av_dictionary, "extra_buffers", 10, 0);

    AVFormatContext *input_ctx = nullptr;
    input_ctx=avformat_alloc_context();
    assert(input_ctx);
    /*input_ctx->video_codec_id=AV_CODEC_ID_H264;
    input_ctx->flags |= AVFMT_FLAG_FLUSH_PACKETS;
    input_ctx->flags |= AVFMT_FLAG_NOBUFFER;*/
    //input_ctx->avio_flags = AVIO_FLAG_DIRECT;
    //input_ctx->flags |= AVFMT_FLAG_NOBUFFER;// | AVFMT_FLAG_FLUSH_PACKETS;

    //input_ctx->flags |= AVFMT_FLAG_NOFILLIN;
    //input_ctx->flags |= AVFMT_FLAG_NOPARSE;
    //input_ctx->flags |= AVFMT_FLAG_NONBLOCK;

    // open the input file
    if (avformat_open_input(&input_ctx,in_filename.c_str(), NULL, &av_dictionary) != 0) {
        qDebug()<< "Cannot open input file ["<<in_filename.c_str()<<"]";
        avformat_close_input(&input_ctx);
        // sleep a bit before returning in this case, to not occupy a full CPU thread just trying
        // to open a file/stream that doesn't exist / is ill-formated
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return -1;
    }
    qDebug()<<"done avformat_open_input["<<in_filename.c_str()<<"]";

    if (avformat_find_stream_info(input_ctx, NULL) < 0) {
        qDebug()<< "Cannot find input stream information.";
        avformat_close_input(&input_ctx);
        return -1;
    }
    qDebug()<<"done avformat_find_stream_info";
    int ret=0;
    // find the video stream information
#if LIBAVFORMAT_VERSION_MAJOR < 59 || (LIBAVFORMAT_VERSION_MAJOR == 59 && LIBAVFORMAT_VERSION_MINOR == 0 && LIBAVFORMAT_VERSION_MICRO < 100)
     ret = av_find_best_stream(input_ctx, AVMEDIA_TYPE_VIDEO, -1, -1, /* (AVCodec**) &decoder */ NULL, 0);
#else
    ret = av_find_best_stream(input_ctx, AVMEDIA_TYPE_VIDEO, -1, -1,(const AVCodec**) &decoder, 0);
#endif
    if (ret < 0) {
        qDebug()<< "Cannot find a video stream in the input file";
        avformat_close_input(&input_ctx);
        return -1;
    }
// TURN ON HERE
bool UseHW=true;

    decoder = UseHW ?  decoder = avcodec_find_decoder_by_name("hevc_qsv") : avcodec_find_decoder(AV_CODEC_ID_H265) ;

    qDebug()<<"done av_find_best_stream:"<<ret;
    const int video_stream = ret;

    if(!(decoder->id==AV_CODEC_ID_H264 || decoder->id==AV_CODEC_ID_H265 || decoder->id==AV_CODEC_ID_MJPEG)){
      qDebug()<<"We only do h264,h265 and mjpeg in this project";
      avformat_close_input(&input_ctx);
      return 0;
    }

    const AVHWDeviceType kAvhwDeviceType = AV_HWDEVICE_TYPE_QSV;
    //const AVHWDeviceType kAvhwDeviceType = AV_HWDEVICE_TYPE_VAAPI;

    bool is_mjpeg=false;
    if(decoder->id==AV_CODEC_ID_H265){
        qDebug()<<"H265 decode";
        qDebug()<<all_hw_configs_for_this_codec(decoder).c_str();
        //wanted_hw_pix_fmt = AV_PIX_FMT_DRM_PRIME;
        //wanted_hw_pix_fmt = AV_PIX_FMT_YUV420P;//vaapi_vld(46),vdpau(100),cuda(119),yuv420p(0),
        wanted_hw_pix_fmt = AV_PIX_FMT_NV12;

        //decoder = avcodec_find_decoder_by_name("hevc_qsv");        
    }else{
        assert(true);
        avformat_close_input(&input_ctx);
        return 0;
    }

    if (!(decoder_ctx = avcodec_alloc_context3(decoder))){
        qDebug()<<"avcodec_alloc_context3 failed";
        avformat_close_input(&input_ctx);
        return -1;
    }

    // Always request low delay decoding
   // decoder_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
    // Allow display of corrupt frames and frames missing references
   // decoder_ctx->flags |= AV_CODEC_FLAG_OUTPUT_CORRUPT;
   // decoder_ctx->flags2 |= AV_CODEC_FLAG2_SHOW_ALL;
   // decoder_ctx->codec_id = AV_CODEC_ID_HEVC;

    AVStream *video = input_ctx->streams[video_stream];

    //THIS IS IMPORTANT! Without it I get  Error initializing the MFX video decoder: unsupported (-3)
    //DISABLE ONLY TO TEST!
    if (avcodec_parameters_to_context(decoder_ctx, video->codecpar) < 0){
        avformat_close_input(&input_ctx);
        return -1;
    }

    //decoder_ctx->extradata=video->codecpar->extradata;
    //decoder_ctx->extradata_size=video->codecpar->extradata_size;
/*
    decoder_ctx->extradata = (uint8_t*) malloc(video->codecpar->extradata_size * sizeof(uint8_t));
    memcpy(decoder_ctx->extradata, video->codecpar->extradata, video->codecpar->extradata_size);
    decoder_ctx->extradata_size=video->codecpar->extradata_size;
    printHex(decoder_ctx->extradata,decoder_ctx->extradata_size);
*/
    //saveBufferToFile("/home/home/Videos/extra.hex",decoder_ctx->extradata,decoder_ctx->extradata_size);

    //Custom preset
    //decoder_ctx->extradata = readFileToBuffer("/home/home/Videos/rtp_cfg.hex",&decoder_ctx->extradata_size);
    printHex(decoder_ctx->extradata,decoder_ctx->extradata_size);

    //decoder_ctx->pix_fmt = AVPixelFormat.PIX_FMT_YUV420P;
    //decoder_ctx->flags2 |= 0x00008000;//CODEC_FLAG2_CHUNKS

    //Try to set params manually
    /*
    decoder_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    decoder_ctx->width=1920;
    decoder_ctx->height=1080;
    decoder_ctx->profile=1;
    decoder_ctx->level=150;
    decoder_ctx->chroma_sample_location = AVCHROMA_LOC_LEFT;
    decoder_ctx->color_range=AVCOL_RANGE_MPEG;
    */
    print_codec_parameters(video->codecpar);

    std::string selected_decoding_type="?";    

    decoder_ctx->get_format  = UseHW ? get_qsv_format : get_sw_format; //get_qsv_format ; //get_hw_format; // get_qsv_format ; //get_sw_format;
    if (hw_decoder_init(decoder_ctx, kAvhwDeviceType) < 0){
          qDebug()<<"HW decoder init failed,fallback to SW decode";
          selected_decoding_type="SW(HW failed)";

          wanted_hw_pix_fmt= AV_PIX_FMT_YUV420P;
        }else{
            selected_decoding_type="HW";
        }   
    // A thread count of 1 reduces latency for both SW and HW decode
    //decoder_ctx->thread_count = 1;

    av_log_set_level(AV_LOG_TRACE);

   if ((ret = avcodec_open2(decoder_ctx, decoder, nullptr)) < 0) {
        qDebug()<<"Failed to open codec for stream ";//<< video_stream;
        avformat_close_input(&input_ctx);
        return -1;
    }
    AVPacket packet;
    // actual decoding and dump the raw data
    const auto decodingStart=std::chrono::steady_clock::now();
    int nFeedFrames=0;
    auto lastFrame=std::chrono::steady_clock::now();
    reset_before_decode_start();
    DecodingStatistcs::instance().set_decoding_type(selected_decoding_type.c_str());


    bool UseRTP=true;
    AVPacket *pkt;
    AVCodecParserContext *parser;
    if (UseRTP){

        parser = av_parser_init(decoder->id);
        if (!parser) {
            fprintf(stderr, "parser not found\n");
            //exit(1);
        }

        if(settings.generic.qopenhd_switch_primary_secondary)
            stream_config=settings.secondary_stream_config;    
        // This thread pulls frame(s) from the rtp decoder and therefore should have high priority
        SchedulingHelper::setThreadParamsMaxRealtime();
        pkt=av_packet_alloc();
        assert(pkt!=nullptr);
        qDebug()<<"AVCodecDecoder::open_and_decode_until_error_custom_rtp()-begin loop";
        m_rtp_receiver=std::make_unique<RTPReceiver>(stream_config.udp_rtp_input_port,stream_config.udp_rtp_input_ip_address,stream_config.video_codec==1,settings.generic.dev_feed_incomplete_frames_to_decoder);
        reset_before_decode_start();
    }
    bool has_keyframe_data=false;
    bool StartWithIDRFrameOnly=false;
    while (ret >= 0) {
        if(request_restart){
            request_restart=false;
            // Since we do streaming and SPS/PPS come in regular intervals, we can just cancel and restart at any time.
            break;
        }

        //if (nFeedFrames%240==1)
        //    UseRTP=!UseRTP;

        if (UseRTP && ((nFeedFrames/240)%2==0)){
            std::shared_ptr<std::vector<uint8_t>> keyframe_buf;
            if(!has_keyframe_data){
                keyframe_buf=m_rtp_receiver->get_config_data();
                if(keyframe_buf==nullptr){
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                /*
                 Stupid Intel QSV driver needs VPS+SPS+PPS followed immediately by a an IDR Slice - otherwise it breaks and gives Unsupported(-3) error !
                 It needs them all in one single AVPacket!!!
                 Took me a week to discover...
                 */

                qDebug()<<"Got decode data (before keyframe)";

                /*
                pkt->data = (uint8_t*) malloc(keyframe_buf->size() + AV_INPUT_BUFFER_PADDING_SIZE);
                memcpy(pkt->data, keyframe_buf->data(), keyframe_buf->size());
                pkt->data=keyframe_buf->data();
                pkt->size=keyframe_buf->size();
                printHex(pkt->data , pkt->size);
                */
                saveBufferToFile("/home/home/Videos/rtp_cfg.hex",keyframe_buf->data(),keyframe_buf->size());

                //decode_config_data(pkt);
                has_keyframe_data=true;
                StartWithIDRFrameOnly=true;
                //continue;
            }


            auto buf =m_rtp_receiver->get_next_frame(std::chrono::milliseconds(kDefaultFrameTimeout));
            if(buf==nullptr)// No buff after X seconds
                continue;

            if (StartWithIDRFrameOnly){//Stupid Intel QSV driver needs VPS+SPS+PPS followed immediately by a an IDR Slice in one AVPacket
                if (buf->get_nal().getData()[4]==0x26 && buf->get_nal().getData()[5]==0x01){

                    pkt->data = (uint8_t*) malloc(keyframe_buf->size() + buf->get_nal().getSize() + AV_INPUT_BUFFER_PADDING_SIZE);
                    memcpy(pkt->data, keyframe_buf->data(), keyframe_buf->size()); //Video info

                    memcpy(pkt->data + keyframe_buf->size() , buf->get_nal().getData(), buf->get_nal().getSize());//IDR Slice

                    pkt->size=keyframe_buf->size() + buf->get_nal().getSize();
                    printHex(pkt->data , pkt->size);
                    saveBufferToFile("/home/home/Videos/magic_rtp.hex",pkt->data,pkt->size);

                    decode_config_data(pkt);
                    StartWithIDRFrameOnly=false;
                }else
                    continue;
            }

            if (false){
                ret = av_parser_parse2(parser, decoder_ctx, &pkt->data, &pkt->size,
                                   (uint8_t*)buf->get_nal().getData(), buf->get_nal().getSize(), AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
            }else{
                pkt->data=(uint8_t*)buf->get_nal().getData();
                pkt->size=buf->get_nal().getSize();
            }

            //qDebug()<<"Got "<<debug_av_packet(pkt).c_str();
            //pkt->dts=0;
            //pkt->duration=0;
            //pkt->flags=0;
            //pkt->pos=0;
            //pkt->pts=0;
            nFeedFrames++;
            saveBufferToFile("/home/home/Videos/pckt_rtp.hex",pkt->data,pkt->size);
            ret = decode_and_wait_for_frame(pkt);

            ret=1;
            continue;
        }        

        if ((ret = av_read_frame(input_ctx, &packet)) < 0){
            qDebug()<<"av_read_frame returned:"<<ret<<" "<<av_error_as_string(ret).c_str();
            if(ret==-110){ //-110   Connection timed out
                ret=0;
                continue;
            }
            break;
        }
        //qDebug()<<"Got av_packet"<<debug_av_packet(&packet).c_str();
        if(false){
             qDebug()<<"Got "<<debug_av_packet(&packet).c_str();
        }else{
            //std::vector<uint8_t> as_buff(packet.data,packet.data+packet.size);
            //qDebug()<<"Packet:"<<StringHelper::vectorAsString(as_buff).c_str()<<"\n";

            if (video_stream == packet.stream_index){
            //if(true){
                int limitedFrameRate=settings.generic.dev_limit_fps_on_test_file;
                if(settings.generic.dev_test_video_mode==QOpenHDVideoHelper::VideoTestMode::DISABLED){
                    // never limit the fps on decode when doing live streaming !
                    limitedFrameRate=-1;
                }
                if(limitedFrameRate>0){
                    const long frameDeltaNs=1000*1000*1000 / limitedFrameRate;
                    while (std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-lastFrame).count()<frameDeltaNs){
                        // busy wait
                    }
                    lastFrame=std::chrono::steady_clock::now();
                }
                saveBufferToFile("/home/home/Videos/pckt_file.hex",packet.data,packet.size);
                packet.dts=0;
                packet.duration=0;
                packet.flags=0;
                packet.pos=0;
                packet.pts=0;

                nFeedFrames++;
                if (nFeedFrames==1){//Only the first frames goes in!
                    printHex(pkt->data , (pkt->size>200)?200:pkt->size);
                    //nFeedFrames=241;
                    packet.size=85 + AV_INPUT_BUFFER_PADDING_SIZE;
                }

                ret = decode_and_wait_for_frame(&packet);

                if(limitedFrameRate>0){
                    const uint64_t runTimeMs=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-decodingStart).count();
                    const double runTimeS=runTimeMs/1000.0f;
                    const double fps=runTimeS==0 ? 0 : nFeedFrames/runTimeS;
                    //qDebug()<<"Fake fps:"<<fps;
                }
            }
        }
         av_packet_unref(&packet);
    }
    qDebug()<<"Broke out of the queue_data_dequeue_frame loop";
    //m_pull_frames_from_ffmpeg_thread->join();
    //m_pull_frames_from_ffmpeg_thread=nullptr;
    // flush the decoder - not needed
    //packet.data = NULL;
    //packet.size = 0;
    //ret = decode_and_wait_for_frame(&packet);
    DecodingStatistcs::instance().set_decode_time("-1");
    DecodingStatistcs::instance().set_primary_stream_frame_format("-1");
    avcodec_free_context(&decoder_ctx);
    qDebug()<<"avcodec_free_context done";
    avformat_close_input(&input_ctx);
    qDebug()<<"avformat_close_input_done";
    return 0;
}


// https://ffmpeg.org/doxygen/3.3/decode_video_8c-example.html
void AVCodecDecoder::open_and_decode_until_error_custom_rtp(const QOpenHDVideoHelper::VideoStreamConfig settings)
{

    // this is always for primary video, unless switching is enabled
    auto stream_config=settings.primary_stream_config;
    if(settings.generic.qopenhd_switch_primary_secondary){
        stream_config=settings.secondary_stream_config;
    }

    // This thread pulls frame(s) from the rtp decoder and therefore should have high priority
    SchedulingHelper::setThreadParamsMaxRealtime();
    av_log_set_level(AV_LOG_TRACE);
     assert(stream_config.video_codec==QOpenHDVideoHelper::VideoCodecH264 || stream_config.video_codec==QOpenHDVideoHelper::VideoCodecH265);
     if(stream_config.video_codec==QOpenHDVideoHelper::VideoCodecH264){
         decoder = avcodec_find_decoder(AV_CODEC_ID_H264);
     }else if(stream_config.video_codec==QOpenHDVideoHelper::VideoCodecH265){
         decoder = avcodec_find_decoder(AV_CODEC_ID_H265);     
     }
     if (!decoder) {
         qDebug()<< "AVCodecDecoder::open_and_decode_until_error_custom_rtp: Codec not found";
         return;
     }
     // ----------------------
     bool use_pi_hw_decode=false;
     bool IntelQSV_HW_decode=false;
     if (decoder->id == AV_CODEC_ID_H264) {
         qDebug()<<"H264 decode";
         qDebug()<<all_hw_configs_for_this_codec(decoder).c_str();
         if(!stream_config.enable_software_video_decoder){
             auto tmp = avcodec_find_decoder_by_name("h264_mmal");
             if(tmp!=nullptr){
                 decoder = tmp;
                 wanted_hw_pix_fmt = AV_PIX_FMT_MMAL;
                 use_pi_hw_decode=true;
             }else{
                 wanted_hw_pix_fmt = AV_PIX_FMT_YUV420P;
             }
         }else{
             wanted_hw_pix_fmt = AV_PIX_FMT_YUV420P;
         }
     }else if(decoder->id==AV_CODEC_ID_H265){
          qDebug()<<"H265 decode";
          QSettings settingsEx;

          bool aaa = settingsEx.value("enable_software_video_decoder",false).toBool();
          if(  !stream_config.enable_software_video_decoder){ // enable_software_video_decoder never set?
             qDebug()<<all_hw_configs_for_this_codec(decoder).c_str();
             // HW format used by rpi h265 HW decoder
             wanted_hw_pix_fmt = AV_PIX_FMT_DRM_PRIME;
             use_pi_hw_decode=true;

             //To Do . Need a switch to enable HW decode with intel QSV
             bool rrr = settingsEx.value("qopenhd_primary_video_force_sw",false).toBool();
             const AVCodec* hevc_qsv = avcodec_find_decoder_by_name("hevc_qsv");
             bool no_stbc = settingsEx.value("dev_wb_show_no_stbc_enabled_warning", false).toBool();//ToDo find a config !
             //settings.primary_stream_config.enable_software_video_decoder
             if ((!no_stbc) && hevc_qsv!=NULL){
                 wanted_hw_pix_fmt = AV_PIX_FMT_NV12;
                 decoder=hevc_qsv;
                 IntelQSV_HW_decode=true;
                 qDebug()<<"AVCodecDecoder::Intel HW decoding available.";
             }
         }else{

         }
     }


     // ------------------------------------
     decoder_ctx = avcodec_alloc_context3(decoder);
     if (!decoder_ctx) {
         qDebug()<< "AVCodecDecoder::open_and_decode_until_error_custom_rtp: Could not allocate video codec context";
         return;
     }
     // ----------------------------------
    // From moonlight-qt. However, on PI, this doesn't seem to make any difference, at least for H265 decode.
    // (I never measured h264, but don't think there it is different).
    // Always request low delay decoding
    decoder_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
    //decoder_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    // Allow display of corrupt frames and frames missing references
    decoder_ctx->flags |= AV_CODEC_FLAG_OUTPUT_CORRUPT;
    decoder_ctx->flags2 |= AV_CODEC_FLAG2_SHOW_ALL;
    // --------------------------------------


    // --------------------------------------
    std::string selected_decoding_type="?";
     
    if(use_pi_hw_decode){
        decoder_ctx->get_format  = IntelQSV_HW_decode ? get_qsv_format:get_hw_format;
        if (hw_decoder_init(decoder_ctx, IntelQSV_HW_decode ? AV_HWDEVICE_TYPE_QSV : AV_HWDEVICE_TYPE_DRM) < 0){  //Enable Intel QSV HW Decode
          qDebug()<<"HW decoder init failed,fallback to SW decode";
          selected_decoding_type="SW(HW failed)";
          assert(true);
        }else{
            selected_decoding_type="HW";
        }
    }else{
        decoder_ctx->get_format  = get_hw_format;//this is SW decoding
        selected_decoding_type="SW";
    }
    // A thread count of 1 reduces latency for both SW and HW decode, for HW Intel it is controlled by the driver
    decoder_ctx->thread_count = IntelQSV_HW_decode ? 0 : 1;
    av_log_set_level(AV_LOG_TRACE);
    // ---------------------------------------

     if (avcodec_open2(decoder_ctx, decoder, NULL) < 0) {
         fprintf(stderr, "Could not open codec\n");
         avcodec_free_context(&decoder_ctx);
         return;
     }
     qDebug()<<"AVCodecDecoder::open_and_decode_until_error_custom_rtp()-begin loop";
     m_rtp_receiver=std::make_unique<RTPReceiver>(stream_config.udp_rtp_input_port,stream_config.udp_rtp_input_ip_address,stream_config.video_codec==1,settings.generic.dev_feed_incomplete_frames_to_decoder);

     reset_before_decode_start();
     DecodingStatistcs::instance().set_decoding_type(selected_decoding_type.c_str());
     AVPacket *pkt=av_packet_alloc();
     assert(pkt!=nullptr);
     bool has_keyframe_data=false;
     int InitWithIDRFrame=IntelQSV_HW_decode?1:0;
     std::shared_ptr<std::vector<uint8_t>> keyframe_buf;

     while(true){
         // We break out of this loop if someone requested a restart
         if(request_restart){
             request_restart=false;
             goto finish;
         }
         // or the decode config changed and we need a restart
         if(m_rtp_receiver->config_has_changed_during_decode){
             qDebug()<<"Break/Restart,config has changed during decode";
             goto finish;
         }
         //std::this_thread::sleep_for(std::chrono::milliseconds(3000));

         if(!has_keyframe_data){
              keyframe_buf=m_rtp_receiver->get_config_data();
              if(keyframe_buf==nullptr){
                  std::this_thread::sleep_for(std::chrono::milliseconds(100));
                  continue;
              }
              has_keyframe_data=true;
              if (InitWithIDRFrame>0){
                    InitWithIDRFrame=2;
              }else{
                qDebug()<<"Got decode data (before keyframe)";
                pkt->data=keyframe_buf->data();
                pkt->size=keyframe_buf->size();
                decode_config_data(pkt);

                continue;
              }
         }else{             
             auto buf =m_rtp_receiver->get_next_frame(std::chrono::milliseconds(kDefaultFrameTimeout));
             if(buf==nullptr){
                 // No buff after X seconds
                 continue;
             }
             if(InitWithIDRFrame==2){//Stupid Intel QSV driver needs VPS+SPS+PPS followed immediately by a IDR Slice in ONE AVPacket
                 if ((buf->get_nal().getData()[4]==0x26 && buf->get_nal().getData()[5]==0x01) || // the prefix is 00 00 00 01
                     (buf->get_nal().getData()[3]==0x26 && buf->get_nal().getData()[4]==0x01)//the prefix can be 00 00 01                 
                 ){//is this an IDR frame? Stick them together
                    pkt->data = (uint8_t*) malloc(keyframe_buf->size() + buf->get_nal().getSize() + AV_INPUT_BUFFER_PADDING_SIZE);
                    memcpy(pkt->data, keyframe_buf->data(), keyframe_buf->size()); //Video info
                    memcpy(pkt->data + keyframe_buf->size() , buf->get_nal().getData(), buf->get_nal().getSize());//IDR Slice
                    pkt->size=keyframe_buf->size() + buf->get_nal().getSize();                    
                    //saveBufferToFile("/home/home/Videos/magic_rtp.hex",pkt->data,pkt->size);
                    decode_config_data(pkt);
                    InitWithIDRFrame=1;
                    free(pkt->data);
                }else{//To Do, add a counter here
                    continue;
                }
             }

             //qDebug()<<"Got decode data (after keyframe)";
            pkt->data=(uint8_t*)buf->get_nal().getData();
            pkt->size=buf->get_nal().getSize();
            decode_and_wait_for_frame(pkt,buf->get_nal().creationTime);
             //fetch_frame_or_feed_input_packet();
         }
     }
finish:
     qDebug()<<"AVCodecDecoder::open_and_decode_until_error_custom_rtp()-end loop";
     m_rtp_receiver=nullptr;
     avcodec_free_context(&decoder_ctx);
}


// Test for Hardware decoding
void AVCodecDecoder::open_and_decode_until_error_testHW(const QOpenHDVideoHelper::VideoStreamConfig settings)
{
        std::string selected_decoding_type="?";
    // this is always for primary video, unless switching is enabled
    auto stream_config=settings.primary_stream_config;
    if(settings.generic.qopenhd_switch_primary_secondary){
        stream_config=settings.secondary_stream_config;
    }

      
//--------------vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv------------------
    enum AVHWDeviceType type;
    AVBufferRef *hw_device_ctx = NULL;
    int i;

/*
Available HW :  vdpau
Available HW :  cuda
Available HW :  vaapi
Available HW :  qsv
Available HW :  drm
Available HW :  opencl
*/

/*
    type = av_hwdevice_find_type_by_name("vaapi");
    //type = av_hwdevice_find_type_by_name("qsv");
    if (type == AV_HWDEVICE_TYPE_NONE) {        
        while((type = av_hwdevice_iterate_types(type)) != AV_HWDEVICE_TYPE_NONE)
             qDebug()<<"Available HW : " << av_hwdevice_get_type_name(type);
        //fprintf(stderr, "\n");
        qDebug()<< "ErrorHW:"<<stderr;        
    }else{
        qDebug()<< "get HW success for type: "<<av_hwdevice_get_type_name(type);
    }
*/    
//--------------^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^------------------

    // This thread pulls frame(s) from the rtp decoder and therefore should have high priority
    SchedulingHelper::setThreadParamsMaxRealtime();
    av_log_set_level(AV_LOG_TRACE);
    
   /*
        qDebug()<< "AVCodecDecoder::avcodec_find_decoder";
        // decoder = avcodec_find_decoder(AV_CODEC_ID_H265);
        decoder = avcodec_find_decoder_by_name("hevc_qsv");
        if (!decoder) 
            qDebug()<<"The QSV decoder is not present in libavcodec";        
        else
            qDebug()<<"The hevc_qsv is  present!"; 
        for (i = 0;; i++) {
            const AVCodecHWConfig *config = avcodec_get_hw_config(decoder, i);
            if (!config) {
                qDebug()<<"Decoder " <<decoder->name<< " does not support device type " << av_hwdevice_get_type_name(type);
                break;
            }
            if (config->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX &&
                config->device_type == type) {
                qDebug()<<"HW Decoder " <<decoder->name<< " chosen . " ;
                //hw_pix_fmt = config->pix_fmt;
                break;
            }
        }
   */             
            //wanted_hw_pix_fmt = AV_PIX_FMT_VDPAU;
            //Supported (HW) pixel formats for qsv 
            // qsv(116),nv12(23)
            wanted_hw_pix_fmt = AV_PIX_FMT_NV12;

            //wanted_hw_pix_fmt = AV_PIX_FMT_QSV;
            //wanted_hw_pix_fmt = AV_PIX_FMT_YUV420P;

/*
    ---- TEST ---- Tisho 2023
*/

 // Find video stream and decoder
    /* open the input file */
     
    AVStream *video = NULL;
    int video_stream=0;

     const AVCodec *decoder = NULL;


    int ret;
    AVFormatContext *input_ctx = NULL;

    ret = av_hwdevice_ctx_create(&hw_device_ctx, AV_HWDEVICE_TYPE_QSV, "auto" /*NULL*/, NULL, 0);
     if (ret < 0) {
         //fprintf(stderr, "Failed to create a QSV device. Error code: %s\n", av_err2str(ret));
         return;
     }


    AVDictionary* av_dictionary=nullptr;
    av_dict_set(&av_dictionary, "protocol_whitelist", "udp,file,hevc,rtp,crypto", 0);
     //const AVInputFormat* format = av_find_input_format("sdp");
      auto format = av_find_input_format("sdp");
    if (avformat_open_input(&input_ctx,"/home/home/Videos/60a.sdp", format, &av_dictionary) != 0) {
              return;
    }

    if (avformat_find_stream_info(input_ctx, NULL) < 0) {
        qDebug()<< "Cannot find input stream information.";
        avformat_close_input(&input_ctx);
        return ;
    }
    /* find the video stream information */
    
    ret = av_find_best_stream(input_ctx, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "Cannot find a video stream in the input file\n");
        goto fin;
    }    

     video_stream = ret;
     video = input_ctx->streams[video_stream];

      decoder = avcodec_find_decoder_by_name("hevc_qsv");
     //decoder = avcodec_find_decoder(video->codecpar->codec_id);

/*
    for (i = 0;; i++) {
        const AVCodecHWConfig *config = avcodec_get_hw_config(decoder, i);
        if (!config) {
            fprintf(stderr, "Decoder %s does not support device type %s.\n",
                    decoder->name, av_hwdevice_get_type_name(type));
           goto fin;
        }
        if (config->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX &&
            config->device_type == type) {
            //hw_pix_fmt = config->pix_fmt;
            break;
        }
    }
*/  
    fin:
// ----------------^^^^^^^^^ Find video stream and decoder ^^^^^^^^^^^-------------

     if (!(decoder_ctx = avcodec_alloc_context3(decoder))){                
         qDebug()<< "AVCodecDecoder::open_and_decode_until_error_custom_rtp: Could not allocate video codec context";
         return;
     }

     /*
    decoder_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
    decoder_ctx->flags |= AV_CODEC_FLAG_OUTPUT_CORRUPT;
    decoder_ctx->flags2 |= AV_CODEC_FLAG2_SHOW_ALL;
*/

    //if ((ret = avcodec_parameters_to_context(decoder_ctx, video->codecpar)) < 0) {
       //  fprintf(stderr, "avcodec_parameters_to_context error. Error code: %s\n", av_err2str(ret));
     //   return ;
    // }
     decoder_ctx->framerate = av_guess_frame_rate(input_ctx, video, NULL);
    decoder_ctx->hw_device_ctx = av_buffer_ref(hw_device_ctx);
 
     if (!decoder_ctx->hw_device_ctx) {
         fprintf(stderr, "A hardware device reference create failed.\n");
         return ;//AVERROR(ENOMEM);
     }
     decoder_ctx->get_format    = get_hw_format;
     decoder_ctx->pkt_timebase = video->time_base;

    //av_dump_format(input_ctx , 0, "/home/home/Videos/15Mbit.mov", 0);
    decoder_ctx->codec_id = AV_CODEC_ID_HEVC;
     if ((ret = avcodec_open2(decoder_ctx, decoder, NULL)) < 0){
         fprintf(stderr, "Failed to open codec for decoding. Error code: %d\n", ret);  
         return ;
    }

     qDebug()<<"AVCodecDecoder::open_and_decode_until_error_custom_rtp()-begin loop";
     m_rtp_receiver=std::make_unique<RTPReceiver>(stream_config.udp_rtp_input_port,stream_config.udp_rtp_input_ip_address,stream_config.video_codec==1,settings.generic.dev_feed_incomplete_frames_to_decoder);    

     reset_before_decode_start();
     DecodingStatistcs::instance().set_decoding_type(selected_decoding_type.c_str());
     AVPacket *pkt=av_packet_alloc();
     assert(pkt!=nullptr);
     bool has_keyframe_data=false;
     while(true){
         // We break out of this loop if someone requested a restart
         if(request_restart){
             request_restart=false;
             goto finish;
         }
         // or the decode config changed and we need a restart
         if(m_rtp_receiver->config_has_changed_during_decode){
             qDebug()<<"Break/Restart,config has changed during decode";
             goto finish;
         }
         //std::this_thread::sleep_for(std::chrono::milliseconds(3000));
         if(!has_keyframe_data){
              std::shared_ptr<std::vector<uint8_t>> keyframe_buf=m_rtp_receiver->get_config_data();
              if(keyframe_buf==nullptr){
                  std::this_thread::sleep_for(std::chrono::milliseconds(100));
                  continue;
              }
              qDebug()<<"Got decode data (before keyframe)";
              pkt->data=keyframe_buf->data();
              pkt->size=keyframe_buf->size();
              decode_config_data(pkt);
              has_keyframe_data=true;
              continue;
         }else{
             auto buf =m_rtp_receiver->get_next_frame(std::chrono::milliseconds(kDefaultFrameTimeout));
             if(buf==nullptr){
                 // No buff after X seconds
                 continue;
             }
             //qDebug()<<"Got decode data (after keyframe)";
             pkt->data=(uint8_t*)buf->get_nal().getData();
             pkt->size=buf->get_nal().getSize();
             decode_and_wait_for_frame(pkt,buf->get_nal().creationTime);
             //fetch_frame_or_feed_input_packet();
         }
     }
finish:
     qDebug()<<"AVCodecDecoder::open_and_decode_until_error_custom_rtp()-end loop";
     m_rtp_receiver=nullptr;
     avcodec_free_context(&decoder_ctx);
}



void AVCodecDecoder::timestamp_add_fed(int64_t ts)
{
    m_fed_timestamps_queue.push_back(ts);
    if(m_fed_timestamps_queue.size()>=MAX_FED_TIMESTAMPS_QUEUE_SIZE){
        m_fed_timestamps_queue.pop_front();
    }
}

bool AVCodecDecoder::timestamp_check_valid(int64_t ts)
{
    for(const auto& el:m_fed_timestamps_queue){
        if(el==ts)return true;
    }
    return false;
}

void AVCodecDecoder::timestamp_debug_valid(int64_t ts)
{
    const bool valid=timestamp_check_valid(ts);
    if(valid){
        qDebug()<<"Is a valid timestamp";
    }else{
        qDebug()<<"Is not a valid timestamp";
    }
}

void AVCodecDecoder::dirty_generic_decode_via_external_decode_service(const QOpenHDVideoHelper::VideoStreamConfig& settings)
{
    qopenhd::decode::service::decode_via_external_decode_service(settings,request_restart);
}
