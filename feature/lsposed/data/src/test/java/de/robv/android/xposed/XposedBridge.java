package de.robv.android.xposed;

import java.util.HashMap;
import java.util.Map;

public final class XposedBridge {
    public static boolean disableHooks = false;
    public static Map<String, String> sHookedMethodCallbacks = new HashMap<>();

    private XposedBridge() {
    }
}
