import java.io.*;
import java.sql.*;
import java.util.*;
public class LeakStmt {
    public String run(String sql) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:x");
        Statement s = c.createStatement();
        ResultSet r = s.executeQuery(sql);
        r.next();
        return r.getString(1);
    }
}
