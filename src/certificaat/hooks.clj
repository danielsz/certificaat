(ns certificaat.hooks
  (:require [certificaat.plugins.webroot :as w]
            [certificaat.plugins.report :as r]
            [certificaat.plugins.server :as s]
            [certificaat.plugins.copy-to-path :as cp]
            [certificaat.plugins.diffie-hellman :as dh]
            [certificaat.hooks :as h]))

(defmulti run (fn [hook options] hook))
(defmethod run :before-challenge [_ options]
  (w/webroot options)
  (s/listen options))
(defmethod run :after-request [_ options]
  (r/report options)
  (dh/params options)
  (cp/copy options))
