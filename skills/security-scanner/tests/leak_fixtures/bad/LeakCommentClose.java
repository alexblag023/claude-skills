import java.io.*;
import java.sql.*;
import java.util.*;
public class LeakCommentClose {
    public void q(Connection c) throws SQLException {
        Statement s = c.createStatement();
        s.execute("select 1; s.close();");
        // s.close();
        /* s.close(); */
    }
}
