package okhttp3;

public interface Http2Connection {

    default void removeSetting(int id) {
        setSetting(id, -1);
    }

    void setSetting(int id, int value);

    void setWindowSizeIncrement(long windowSizeIncrement);

    /**
     * @param order eg: m,a,s,p
     */
    void setHeaderOrder(String order);

    void addPriorityFrame(PriorityFrame frame);

}
