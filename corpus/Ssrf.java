public class Ssrf {
    // Opens a user-controlled URL: a server-side request forgery sink.
    public java.io.InputStream fetch(String target) throws Exception {
        java.net.URL url = new java.net.URL(target);
        return url.openConnection().getInputStream();
    }
}
