package okhttp3;

public interface Settings {

    /** HTTP/2: Size in bytes of the table used to decode the sender's header blocks. */
    int HEADER_TABLE_SIZE = 1;

    /** HTTP/2: The peer must not send a PUSH_PROMISE frame when this is 0. */
    int ENABLE_PUSH = 2;

    /** Sender's maximum number of concurrent streams. */
    int MAX_CONCURRENT_STREAMS = 4;

    /** HTTP/2: Size in bytes of the largest frame payload the sender will accept. */
    int MAX_FRAME_SIZE = 5;

    /** HTTP/2: Advisory only. Size in bytes of the largest header list the sender will accept. */
    int MAX_HEADER_LIST_SIZE = 6;

    /** Window size in bytes. */
    int INITIAL_WINDOW_SIZE = 7;

}
