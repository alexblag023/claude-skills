import java.io.*;
import java.sql.*;
import java.util.*;
public class LeakInputStream {
    public int head(File f) {
        try {
            FileInputStream in = new FileInputStream(f);
            return in.read();
        } catch (IOException e) {
            return -1;
        }
    }
}
