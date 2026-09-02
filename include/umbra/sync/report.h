// A device's compaction report, and the sealing that makes it un-forgeable.
//
// ADR 0003 clause 2 requires this to be AUTHENTICATED, not merely transmitted,
// and the reason is written out in ADR 0001: a relay that could inflate a mark
// could induce every device to compact past an operation one of them never
// received. Sealing under the epoch key closes that, because the relay holds no
// key.
//
// WHAT SEALING DOES NOT DO, stated here because it is the thing most likely to
// be assumed: it makes a report un-forgeable, not true. A device that was
// deceived about what it holds will seal that belief honestly. That is why the
// back-pointer chain exists -- it stops the deception upstream of the report.
#ifndef UMBRA_SYNC_REPORT_H_
#define UMBRA_SYNC_REPORT_H_

#include <map>
#include <string>
#include <vector>

#include "umbra/crdt/op_id.h"
#include "umbra/crdt/tree.h"
#include "umbra/crypto/keys.h"

namespace umbra {

// The bytes a DeviceReport travels as. Canonical, so two devices that agree
// about the world produce identical plaintext.
std::string EncodeDeviceReport(const DeviceReport& r);
bool DecodeDeviceReport(const std::string& bytes, DeviceReport* out);

// Seal a report under the content key for `epoch`.
//
// THE DEVICE ID IS THE ASSOCIATED DATA, so a relay cannot take device A's
// sealed report and serve it as device B's. Without that binding the relay
// could not forge a report but could still misattribute one, which is enough to
// move the watermark: B's marks are usually higher than a lagging A's.
CryptoStatus SealDeviceReport(const VaultKeys& keys, Epoch epoch,
                              const DeviceReport& r, std::string* sealed);

// Open one. Returns kAuthFailed if the bytes, the key, the epoch or the claimed
// device do not match what was sealed, and does not distinguish between them.
CryptoStatus OpenDeviceReport(const VaultKeys& keys, Epoch epoch,
                              const ReplicaId& claimed_device,
                              const std::string& sealed, DeviceReport* out);

}  // namespace umbra

#endif  // UMBRA_SYNC_REPORT_H_
