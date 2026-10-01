import java.io.*;
import java.sql.*;
import java.util.*;
public class FinallyNested {
    public void run(Connection c) {
        Statement stmt = null;
        try {
            stmt = c.createStatement();
            stmt.execute("x");
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null) {
                    stmt.close();
                }
            } catch (SQLException e) {
            }
        }
    }
}
