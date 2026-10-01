import java.sql.*;
public class CfgB {
    Connection open() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://h/db", "app", "Sup3rSecret!");
    }
}
