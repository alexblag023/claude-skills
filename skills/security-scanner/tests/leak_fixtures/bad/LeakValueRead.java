import java.io.*;
import java.sql.*;
public class LeakValueRead {
    public Dto load(Connection c) throws SQLException {
        Statement s = c.createStatement();
        ResultSet r = s.executeQuery("x");
        r.next();
        return new Dto(r.getString(1));
    }
}
