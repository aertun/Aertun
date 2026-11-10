// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package telemetry

import "regexp"

// AlertField is the Raw key an event carries the platform's own id for an
// alert in, when the event is an alert another product raised.
//
// It is what lets a finding name the alert it came from (the detection run
// copies it to the evidence's Ref), and so what lets a vendor's AI verdict
// on that alert be joined to the person's decision on the finding. A source
// mapping fills it from the path its Alert names, after the kept fields, so
// a kept field that happens to be called alert cannot stand in for it.
const AlertField = "alert"

// An alert id is an identifier in somebody else's system: letters, digits
// and the separators those identifiers use, never spaces, slashes or
// anything a terminal or a path would read differently.
var alertID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidAlertID reports whether s has the shape of an alert id, the only
// shape an alert id is carried or matched in.
func ValidAlertID(s string) bool { return alertID.MatchString(s) }
