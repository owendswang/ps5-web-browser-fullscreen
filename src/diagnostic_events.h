/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WEB_BROWSER_DIAGNOSTIC_EVENTS_H
#define WEB_BROWSER_DIAGNOSTIC_EVENTS_H
/* Host mocks and historical code can compile without a report collector. */
#ifndef DIAG_STEP
#define DIAG_STEP(...) ((void)0)
#define DIAG_EVENT(...) ((void)0)
#define DIAG_ERROR(...) ((void)0)
#define DIAG_ENGINE(...) ((void)0)
#define DIAG_BYTES(...) ((void)0)
#endif
#endif
