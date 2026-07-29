;;; ============================================================
;;; commands/SayHello.lsp
;;; ------------------------------------------------------------
;;; Prints a greeting at the command line.
;;;
;;; Usage: type SAYHELLO at the command line.
;;;
;;; ============================================================

(vl-load-com)

(defun c:SayHello (/ doc)
  (setq doc (vla-get-ActiveDocument (vlax-get-acad-object)))
  (vla-startundomark doc)
  (princ "\nHello from AutoLISP!")
  (vla-endundomark doc)
  (princ))

(princ "\nSayHello loaded — type SAYHELLO to run.")
(princ)
