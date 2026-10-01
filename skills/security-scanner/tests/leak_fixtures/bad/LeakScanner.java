import java.io.*;
import java.sql.*;
import java.util.*;
public class LeakScanner {
    public String word(File f) throws FileNotFoundException {
        Scanner sc = new Scanner(f);
        return sc.next();
    }
}
