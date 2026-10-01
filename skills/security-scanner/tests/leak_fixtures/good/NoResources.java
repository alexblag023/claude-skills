import java.io.*;
import java.sql.*;
import java.util.*;
public class NoResources {
    public int sum(List<Integer> xs) {
        int t = 0;
        for (int x : xs) { t += x; }
        // Statement s = c.createStatement();  (в комментарии — не ресурс)
        return t;
    }
}
