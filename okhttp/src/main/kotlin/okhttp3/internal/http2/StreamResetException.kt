/*
 * Copyright (C) 2016 Square, Inc.
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

import java.io.IOException

/**
 * Thrown when an HTTP/2 stream is canceled without damage to the socket that carries it.
 *
 * [detail] says what the peer actually sent, when that is more than [errorCode] can tell: a GOAWAY is
 * reported with [ErrorCode.REFUSED_STREAM] for every stream it cuts off, whatever the GOAWAY's own error
 * code, so without it a rate limit (`ENHANCE_YOUR_CALM`), a graceful shutdown (`NO_ERROR`) and a real
 * per-stream refusal all read "stream was reset: REFUSED_STREAM". Callers branch on [errorCode] only; the
 * detail is for the message.
 */
class StreamResetException
  @JvmOverloads
  constructor(
    @JvmField val errorCode: ErrorCode,
    detail: String? = null,
  ) : IOException(if (detail == null) "stream was reset: $errorCode" else "stream was reset: $errorCode ($detail)")
