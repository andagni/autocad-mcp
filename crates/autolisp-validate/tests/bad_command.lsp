;;; A file with deliberate errors for testing the validator.

; Missing quiet-exit, uses CL idioms, bad command prefix.

(defun c:BadExample (/ doc items)
  (setq doc (vla-get-ActiveDocument (vlax-get-acad-object)))

  ; CL idioms that don't exist in AutoLISP
  (let ((x 5))
    (format t "x is ~a" x))

  ; command string without _.  prefix
  (command "LINE" "0,0" "10,10" "")

  ; getint without range check comment
  (setq n (getint "\nHow many? "))

  ; unbalanced paren coming up...
  (foreach item items
    (princ item)
  )  ; <- this one is fine, but we left one open below

(princ "\nBadExample loaded.")
; Note: missing final quiet-exit call.
