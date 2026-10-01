import java.io.*;
import java.sql.*;
import java.util.*;
public class LeakReader {
    public String first(String path) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(path));
        return br.readLine();
    }
}
