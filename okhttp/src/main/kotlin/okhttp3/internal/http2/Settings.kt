/*
 * Copyright (C) 2012 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3.internal.http2

/**
 * Settings describe characteristics of the sending peer, which are used by the receiving peer.
 * Settings are [connection][Http2Connection] scoped.
 */
class Settings {

  /** Flag values. */
  val values = LinkedHashMap<Int, Int>(COUNT)

  /** Returns -1 if unset. */
  val headerTableSize: Int
    get() {
      return values.getOrDefault(HEADER_TABLE_SIZE, -1)
    }

  val initialWindowSize: Int
    get() {
      return values.getOrDefault(INITIAL_WINDOW_SIZE, DEFAULT_INITIAL_WINDOW_SIZE)
    }

  fun clear() {
    values.clear()
  }

  operator fun set(id: Int, value: Int): Settings {
    if(value == -1) {
      values.remove(id)
      return this
    }
    if (id < 0 || id >= COUNT) {
      return this // Discard unknown settings.
    }

    values[id] = value
    return this
  }

  /** Returns true if a value has been assigned for the setting `id`. */
  fun isSet(id: Int): Boolean {
    return values.containsKey(id)
  }

  /** Returns the value for the setting `id`, or 0 if unset. */
  operator fun get(id: Int): Int = values.getOrDefault(id, 0)

  /** Returns the number of settings that have values assigned. */
  fun size(): Int = values.size

  // TODO: honor this setting.
  fun getEnablePush(defaultValue: Boolean): Boolean {
    if(values.containsKey(ENABLE_PUSH)) {
      return values[ENABLE_PUSH] == 1
    }
    return defaultValue
  }

  fun getMaxConcurrentStreams(): Int {
    return values.getOrDefault(MAX_CONCURRENT_STREAMS, Int.MAX_VALUE)
  }

  fun getMaxFrameSize(defaultValue: Int): Int {
    return values.getOrDefault(MAX_FRAME_SIZE, defaultValue)
  }

  fun getMaxHeaderListSize(defaultValue: Int): Int {
    return values.getOrDefault(MAX_HEADER_LIST_SIZE, defaultValue)
  }

  /**
   * Writes `other` into this. If any setting is populated by this and `other`, the
   * value and flags from `other` will be kept.
   */
  fun merge(other: Settings) {
    for (i in 0 until COUNT) {
      if (!other.isSet(i)) continue
      set(i, other[i])
    }
  }

  companion object {
    /**
     * From the HTTP/2 specs, the default initial window size for all streams is 64 KiB. (Chrome 25
     * uses 10 MiB).
     */
    const val DEFAULT_INITIAL_WINDOW_SIZE = 65535

    /** HTTP/2: Size in bytes of the table used to decode the sender's header blocks. */
    const val HEADER_TABLE_SIZE = 1
    /** HTTP/2: The peer must not send a PUSH_PROMISE frame when this is 0. */
    const val ENABLE_PUSH = 2
    /** Sender's maximum number of concurrent streams. */
    const val MAX_CONCURRENT_STREAMS = 4
    /** HTTP/2: Size in bytes of the largest frame payload the sender will accept. */
    const val MAX_FRAME_SIZE = 5
    /** HTTP/2: Advisory only. Size in bytes of the largest header list the sender will accept. */
    const val MAX_HEADER_LIST_SIZE = 6
    /** Window size in bytes. */
    const val INITIAL_WINDOW_SIZE = 7

    /** Total number of settings. */
    const val COUNT = 10
  }
}
