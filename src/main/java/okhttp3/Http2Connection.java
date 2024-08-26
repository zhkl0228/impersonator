package okhttp3;

public interface Http2Connection {

    void setSetting(int id, int value);

    void setWindowSizeIncrement(long windowSizeIncrement);

    /**
     * @param order eg: m,a,s,p
     */
    void setHeaderOrder(String order);

}
