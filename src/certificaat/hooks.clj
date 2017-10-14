(ns certificaat.hooks
  (:require [certificaat.plugins.webroot :as w]
            [certificaat.plugins.report :as r]))

(defmulti run-hooks (fn [hook options] hook))
(defmethod run-hooks :before-challenge [_ {:keys [hooks] :as options}]
  (when (some #{:before-challenge} hooks)
    (w/webroot options)))
(defmethod run-hooks :after-request [_ {:keys [hooks] :as options}]
  (when (some #{:after-request} hooks)
    (r/report options)))

;; (condp #(contains? %2 %1) plugins
;;     :dhparams (println "dhparams")
;;     :email (println "email"))
