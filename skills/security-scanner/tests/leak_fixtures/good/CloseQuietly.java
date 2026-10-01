import java.io.*;
import java.sql.*;
import java.util.*;
public class CloseQuietly {
    public int head(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        try {
            return in.read();
        } finally {
            IOUtils.closeQuietly(in);
        }
    }
}
