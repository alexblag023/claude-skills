public class ErrA {
    public void run() {
        try {
            Integer.parseInt("x");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
