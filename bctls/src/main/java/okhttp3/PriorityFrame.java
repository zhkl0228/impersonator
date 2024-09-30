package okhttp3;

public class PriorityFrame {

    public final int streamId;
    public final int streamDependency;
    public final int weight;

    public PriorityFrame(int streamId, int streamDependency, int weight) {
        this.streamId = streamId;
        this.streamDependency = streamDependency;
        this.weight = weight;
    }

}
