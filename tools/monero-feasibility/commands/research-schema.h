#ifndef KEEPKEY_MONERO_RESEARCH_SCHEMA_H
#define KEEPKEY_MONERO_RESEARCH_SCHEMA_H

#if !defined(EMULATOR) || !defined(KK_MONERO_EMULATOR_RESEARCH) || BITCOIN_ONLY
#error "Monero research commands require an explicitly selected regular emulator"
#endif

#include "messages-monero-research.pb.h"

#define MessageType_MessageType_MoneroGetAddress ((MessageType)540)
#define MessageType_MessageType_MoneroAddress ((MessageType)541)
#define MessageType_MessageType_MoneroGetWatchKey ((MessageType)542)
#define MessageType_MessageType_MoneroWatchKey ((MessageType)543)
#define MessageType_MessageType_MoneroKeyImageExportInitRequest ((MessageType)530)
#define MessageType_MessageType_MoneroKeyImageExportInitAck ((MessageType)531)
#define MessageType_MessageType_MoneroKeyImageSyncStepRequest ((MessageType)532)
#define MessageType_MessageType_MoneroKeyImageSyncStepAck ((MessageType)533)
#define MessageType_MessageType_MoneroKeyImageSyncFinalRequest ((MessageType)534)
#define MessageType_MessageType_MoneroKeyImageSyncFinalAck ((MessageType)535)
#define MessageType_MessageType_MoneroResearchSignTransaction ((MessageType)65000)
#define MessageType_MessageType_MoneroResearchSignedTransaction ((MessageType)65001)

void fsm_msgMoneroGetAddress(MoneroGetAddress *msg);
void fsm_msgMoneroGetWatchKey(MoneroGetWatchKey *msg);
void fsm_msgMoneroKeyImageExportInit(MoneroKeyImageExportInitRequest *msg);
void fsm_msgMoneroKeyImageSyncStep(MoneroKeyImageSyncStepRequest *msg);
void fsm_msgMoneroKeyImageSyncFinal(MoneroKeyImageSyncFinalRequest *msg);
void fsm_msgMoneroResearchSignTransaction(MoneroResearchSignTransaction *msg);

#endif
