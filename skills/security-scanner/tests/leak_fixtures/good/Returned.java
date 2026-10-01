import java.io.*;
import java.sql.*;
import java.util.*;
public class Returned {
    public InputStream open(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        return in;
    }
}
