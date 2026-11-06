package io.github.kidctl.e2efgs;

/** Starts the foreground service and goes away. */
public class Main extends android.app.Activity {
    @Override
    protected void onCreate(android.os.Bundle b) {
        super.onCreate(b);
        startForegroundService(new android.content.Intent(this, Svc.class));
        finish();
    }
}
