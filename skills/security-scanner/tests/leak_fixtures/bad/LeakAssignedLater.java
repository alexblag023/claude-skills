import java.io.*;
import java.sql.*;
import java.util.*;
public class LeakAssignedLater {
    public void ignore(Connection connect, String sql) {
        PreparedStatement action;
        try {
            action = connect.prepareStatement(sql);
            action.execute();
            Statement st = connect.createStatement();
            st.execute("x");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
