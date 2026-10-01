import java.io.*;
import java.sql.*;
import java.util.*;
public class ParentClosed {
    public String run(String sql) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:x");
        try {
            Statement s = c.createStatement();
            ResultSet r = s.executeQuery(sql);
            r.next();
            return r.getString(1);
        } finally {
            c.close();
        }
    }
}
