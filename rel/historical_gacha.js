/*
 * Version-bound Windows PC compatibility for historical gacha visibility.
 *
 * This intentionally changes DateTimeUtil.timeStampNow only while
 * GachaDB.GetValidPoolsEnumerator is executing on the same thread.  Every
 * other consumer of the game clock sees the original value.
 */
"use strict";

const conf = {};
let installed = false;

function publish(kind, payload) {
    send(Object.assign({ source: "historical_gacha", kind: kind }, payload || {}));
}

function installIfReady() {
    if (installed || !conf.activate) return;
    if (!Number.isInteger(conf.content_ts) || conf.content_ts <= 0) return;
    if (!Number.isInteger(conf.get_valid_pools_rva)) return;
    if (!Number.isInteger(conf.timestamp_now_rva)) return;

    const module = Process.getModuleByName("GameAssembly.dll");
    const getValidPools = module.base.add(conf.get_valid_pools_rva);
    const timestampNow = module.base.add(conf.timestamp_now_rva);
    const depthByThread = new Map();

    Interceptor.attach(getValidPools, {
        onEnter() {
            const tid = Process.getCurrentThreadId();
            this.tid = tid;
            depthByThread.set(tid, (depthByThread.get(tid) || 0) + 1);
        },
        onLeave() {
            const depth = (depthByThread.get(this.tid) || 1) - 1;
            if (depth > 0) depthByThread.set(this.tid, depth);
            else depthByThread.delete(this.tid);
        }
    });

    Interceptor.attach(timestampNow, {
        onLeave(retval) {
            const tid = Process.getCurrentThreadId();
            if ((depthByThread.get(tid) || 0) > 0) {
                retval.replace(ptr(conf.content_ts));
            }
        }
    });
    installed = true;
    publish("installed", {
        contentTs: conf.content_ts,
        gameAssemblyBase: module.base.toString(),
        getValidPools: getValidPools.toString(),
        timestampNow: timestampNow.toString()
    });
}

recv(function onMessage(message) {
    if (message.type === "conf") {
        conf[message.k] = message.v;
        try {
            installIfReady();
        } catch (error) {
            publish("disabled", { reason: String(error) });
        }
    }
    recv(onMessage);
});
