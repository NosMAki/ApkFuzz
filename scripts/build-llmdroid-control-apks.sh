#!/usr/bin/env bash
# Build a tiny paired app with a known crash on the Save action.
set -euo pipefail

output=${1:?usage: build-llmdroid-control-apks.sh OUTPUT_DIR}
if [[ -e "$output" ]]; then
  echo "output already exists: $output" >&2
  exit 1
fi
sdk=${ANDROID_SDK_ROOT:-/home/sahar/android-sdk}
build_tools="$sdk/build-tools/34.0.0"
android_jar="$sdk/platforms/android-34/android.jar"
mkdir -p "$output/signing"
chmod 700 "$output/signing"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$output/signing/key.pem" -out "$output/signing/cert.pem" \
  -subj '/CN=APKVulFuzz local control' >/dev/null 2>&1
chmod 600 "$output/signing/key.pem"
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER \
  -in "$output/signing/key.pem" -out "$output/signing/key.pk8"
chmod 600 "$output/signing/key.pk8"

for variant in baseline defect; do
  work="$output/$variant-build"
  mkdir -p "$work/src/org/apkvulfuzz/control" "$work/classes" "$work/dex"
  cat > "$work/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.apkvulfuzz.control">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28" />
  <application android:label="APKVulFuzz Control">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>
EOF
  if [[ "$variant" == defect ]]; then
    action='throw new IllegalStateException("CONTROLLED_SAVE_DEFECT");'
  else
    action='status.setText("Saved");'
  fi
  cat > "$work/src/org/apkvulfuzz/control/MainActivity.java" <<EOF
package org.apkvulfuzz.control;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        TextView status = new TextView(this);
        status.setText("Ready");
        Button save = new Button(this);
        save.setText("Save");
        save.setOnClickListener(view -> { $action });
        layout.addView(status);
        layout.addView(save);
        setContentView(layout);
    }
}
EOF
  javac -source 8 -target 8 -classpath "$android_jar" -d "$work/classes" \
    "$work/src/org/apkvulfuzz/control/MainActivity.java" 2> "$work/javac.log"
  "$build_tools/d8" --lib "$android_jar" --min-api 23 --output "$work/dex" \
    "$work/classes/org/apkvulfuzz/control/MainActivity.class" > "$work/d8.log" 2>&1
  "$build_tools/aapt" package -f -M "$work/AndroidManifest.xml" -I "$android_jar" \
    -F "$work/unsigned.apk" > "$work/aapt.log" 2>&1
  (cd "$work/dex" && "$build_tools/aapt" add ../unsigned.apk classes.dex >/dev/null)
  "$build_tools/apksigner" sign --key "$output/signing/key.pk8" \
    --cert "$output/signing/cert.pem" --out "$output/$variant.apk" "$work/unsigned.apk"
  "$build_tools/apksigner" verify "$output/$variant.apk"
done
sha256sum "$output/baseline.apk" "$output/defect.apk" > "$output/hashes.txt"
echo "built control APKs in $output"
