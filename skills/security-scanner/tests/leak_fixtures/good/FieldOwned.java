import java.io.*;
import java.sql.*;
import java.util.*;
public class FieldOwned {
    private InputStream in;
    public void open(File f) throws IOException {
        FileInputStream tmp = new FileInputStream(f);
        this.in = tmp;
    }
}
