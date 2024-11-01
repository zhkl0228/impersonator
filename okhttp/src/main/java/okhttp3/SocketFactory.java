package okhttp3;

import java.io.IOException;
import java.net.Socket;

public interface SocketFactory {

    Socket newSocket() throws IOException;

}
