import java.io.*;
import java.sql.*;
import java.util.*;
public class Delegated {
    public String read(Process proc) throws IOException {
        InputStreamReader isr = new InputStreamReader(proc.getInputStream());
        BufferedReader br = new BufferedReader(isr);
        try {
            return br.readLine();
        } finally {
            br.close();
        }
    }
}
