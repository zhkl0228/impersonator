/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.impl;

import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.send.Sender;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static tech.kwik.core.common.EncryptionLevel.App;


/**
 * Sends PINGs so the connection does not go idle. Two ways: kwik's own, which keeps the connection alive for a given
 * time in total with a PING at half the peer's idle timeout; and {@link #every}, a PING every given interval for as
 * long as the connection lives.
 */
public class KeepAliveActor {

    private final Clock clock;
    private final VersionHolder quicVersion;
    private final Sender sender;
    private final ScheduledExecutorService scheduler;
    private final Duration pingInterval;
    /** No PING is scheduled from this moment on; {@code null} to keep on for as long as {@link #alive} holds. */
    private final Instant scheduleUntil;
    /** Whether the connection is still there to keep alive; asked before every PING. */
    private final BooleanSupplier alive;

    /**
     * @param quicVersion
     * @param keepAliveTime       the time the connection should be kept alive in seconds - in total, not between
     *                            PINGs: a PING goes out every half {@code peerIdleTimeout}, and only while there is
     *                            more than one such interval of this time left. Shorter than that, none at all.
     * @param peerIdleTimeout     the idle timeout of the peer, in milliseconds
     * @param sender
     */
    public KeepAliveActor(VersionHolder quicVersion, int keepAliveTime, int peerIdleTimeout, Sender sender) {
        this(Clock.systemUTC(), quicVersion, keepAliveTime, peerIdleTimeout, sender, createScheduler());
    }

    KeepAliveActor(Clock clock, VersionHolder quicVersion, int keepAliveTime, int peerIdleTimeout, Sender sender, ScheduledExecutorService scheduler) {
        this(clock, quicVersion, sender, scheduler, Duration.ofSeconds(peerIdleTimeout / 1000 / 2),
                clock.instant().plusSeconds(keepAliveTime - peerIdleTimeout / 1000 / 2), () -> true);
    }

    private KeepAliveActor(Clock clock, VersionHolder quicVersion, Sender sender, ScheduledExecutorService scheduler,
                           Duration pingInterval, Instant scheduleUntil, BooleanSupplier alive) {
        this.clock = clock;
        this.quicVersion = quicVersion;
        this.sender = sender;
        this.scheduler = scheduler;
        this.pingInterval = pingInterval;
        this.scheduleUntil = scheduleUntil;
        this.alive = alive;

        scheduleNextPing();
    }

    /**
     * A PING every {@code pingInterval} for as long as {@code alive} holds - what a connection kept open for reuse
     * needs, and what the other constructor cannot say: its time is a total, so hysteria2's "every 10 seconds"
     * passed to it as 10 was a total shorter than one interval, and not a single PING went out. The shared
     * connection then idled out between requests, and a request reusing it just as the server dropped it failed
     * one round trip in with "Connection closed".
     *
     * @param alive asked before every PING; once false, nothing more is sent and the thread ends, so a connection
     *              that ended any other way than through {@link #shutdown} does not leave it running
     */
    static KeepAliveActor every(VersionHolder quicVersion, Duration pingInterval, Sender sender, BooleanSupplier alive) {
        return every(quicVersion, pingInterval, sender, alive, createScheduler());
    }

    static KeepAliveActor every(VersionHolder quicVersion, Duration pingInterval, Sender sender, BooleanSupplier alive,
                                ScheduledExecutorService scheduler) {
        return new KeepAliveActor(Clock.systemUTC(), quicVersion, sender, scheduler, pingInterval, null, alive);
    }

    private void ping() {
        if (!alive.getAsBoolean()) {
            scheduler.shutdown();
            return;
        }
        sender.send(new PingFrame(quicVersion.getVersion()), App);
        sender.flush();

        scheduleNextPing();
    }

    private void scheduleNextPing() {
        if (scheduleUntil == null || clock.instant().isBefore(scheduleUntil)) {
            scheduler.schedule(this::ping, pingInterval.toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    public void shutdown() {
        scheduler.shutdown();
    }

    private static ScheduledExecutorService createScheduler() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "kwik-keep-alive");
            // A connection pinged for as long as it lives must not be what keeps the JVM from exiting.
            thread.setDaemon(true);
            return thread;
        });
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        return executor;
    }
}
