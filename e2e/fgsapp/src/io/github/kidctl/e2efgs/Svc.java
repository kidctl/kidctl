package io.github.kidctl.e2efgs;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.IBinder;

/** A foreground service that does nothing but run. */
public class Svc extends Service {
    @Override
    public int onStartCommand(Intent i, int flags, int id) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("e2e", "e2e", NotificationManager.IMPORTANCE_LOW));
        Notification n = new Notification.Builder(this, "e2e")
            .setContentTitle("kidctl e2e fgs")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .build();
        startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent i) {
        return null;
    }
}
