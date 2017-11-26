(ns certificaat.hooks
  (:require [certificaat.plugins.webroot :as w]
            [certificaat.plugins.report :as r]
            [certificaat.plugins.server :as s]
            [certificaat.util.diffie-hellman :as dh]
            [certificaat.hooks :as h]))

(defmulti run-hooks (fn [hook options] hook))
(defmethod run-hooks :before-challenge [_ {:keys [hooks] :as options}]
  (when (some #{:before-challenge} hooks)
    (w/webroot options)
    (s/listen options)))
(defmethod run-hooks :after-request [_ {:keys [hooks] :as options}]
  (when (some #{:after-request} hooks)
    (r/report options)
    (dh/params options)))
