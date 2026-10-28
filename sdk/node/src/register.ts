// Zero-config entry point:
//
//   TT_ENROLL_URL=https://tt-core.internal:4318 TT_ENROLL_TOKEN=tte_... TT_HMAC_KEY_FILE=/run/tt/key \
//     node --import @traffic-twin/sdk/register app.js
//
// (or `node --require @traffic-twin/sdk/register app.js` for CommonJS apps).
// Hooks are installed synchronously before the app loads; enrollment, heartbeat and policy
// fetch run in the background and never delay or break the app. TT_DISABLED=1 turns it off.

import { isMainThread, workerData } from 'node:worker_threads';
import { start } from './index.js';

const ownWorker = !isMainThread && (workerData as { ttSanitizer?: boolean } | null)?.ttSanitizer === true;

if (!ownWorker && !/^(1|true|yes)$/i.test(process.env.TT_DISABLED ?? '')) {
  start().catch(() => {
    // never surface SDK failures to the app
  });
}
