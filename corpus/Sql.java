public class Sql {
    // String-concatenated SQL: a classic SQL injection sink.
    public void query(java.sql.Connection c, String name) throws Exception {
        String q = "SELECT * FROM users WHERE name = '" + name + "'";
        c.createStatement().executeQuery(q);
    }
}
