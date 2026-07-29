;;; ============================================================
;;; commands/standalone_command.lsp
;;; ------------------------------------------------------------
;;; A self-contained command fixture using documented built-ins.
;;; ============================================================

(vl-load-com)

(defun c:Standalone (/ n)
  (setq n 0)
  (vlax-for ent (vla-get-modelspace (vla-get-activedocument (vlax-get-acad-object)))
    (setq n (1+ n)))
  (princ (strcat "\nCounted " (itoa n) " entities."))
  (princ))

(princ "\nStandalone loaded — type STANDALONE to run.")
(princ)
