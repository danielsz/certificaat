(ns certificaat.fsm
  (:require [golem.stack :refer [state-machine update-state target-state]]
            [certificaat.utils :refer [exit error-msg]]
            [certificaat.kung-fu :as k]
            [certificaat.hooks :as h]
            [clojure.core.async :refer [<!!]]
            [certificaat.plugins.webroot :as w])
  (:import clojure.lang.ExceptionInfo
           (org.shredzone.acme4j.exception AcmeServerException AcmeUnauthorizedException AcmeRateLimitedException)
           org.shredzone.acme4j.Status))

(def setup k/setup)
(defn register [options] (k/register options))
(defn authorize [{config-dir :config-dir domain :domain :as options}]
  (let [reg (k/register options)]
    (doseq [[name auth challenges] (k/authorize options reg)
            i (range (count challenges))
            challenge challenges
            :let [explanation (k/explain challenge name)]]
      (println explanation)
      (spit (str config-dir domain "/" name "." (.getType challenge) ".challenge.txt") explanation)
      (spit (str config-dir domain "/challenge." name "." i ".uri") (.getLocation challenge))
      (spit (str config-dir domain "/authorization." name ".uri") (.getLocation auth)))))

(defn accept-challenges [options]
  (try
      (doseq [c (k/challenge options)
              :let [resp (<!! c)]]
        (if (= Status/VALID resp)
          (println "Well done, challenge completed.")
          (println "Sorry, challenge failed." resp)))
      (catch AcmeServerException e (exit 1 (.getMessage e)))))

(defn request [options]
  (let [reg (k/register options)]
    (try 
      (k/request options reg) ; will throw AcmeUnauthorizedException if the authorizations of some or all involved domains have expired
      (catch AcmeRateLimitedException e (exit 1 (.getMessage e)))
      (catch AcmeUnauthorizedException e (exit 1 (.getMessage e)))) ))


(defn run [{config-dir :config-dir domain :domain :as options}]
  (let [state-table {:find-certificate [{:valid-when [#(k/valid? (str config-dir domain "/certificate.uri") options)]
                                         :side-effect #(exit 0 "Nothing left to do at this point in time.")
                                         :next-state nil}
                                        {:valid-when []
                                         :side-effect #(do)
                                         :next-state :find-authorization}]
                     :find-authorization [{:valid-when [#(let [auth (str config-dir domain "/authorization." domain ".uri")]
                                                           (and (k/valid? auth options) (k/pending? auth options)))]
                                           :side-effect #(accept-challenges options)
                                           :next-state :find-authorization}
                                          {:valid-when [#(k/valid? (str config-dir domain "/authorization." domain ".uri") options)]
                                           :side-effect #(do (request options)
                                                             (h/run-hooks :after-request options))
                                           :next-state :find-certificate}                       
                                          {:valid-when [#(k/valid? (str config-dir "registration.uri") options)]
                                           :side-effect #(do (authorize options)
                                                             (h/run-hooks :before-challenge options))
                                           :next-state :find-authorization}
                                          {:valid-when []
                                           :side-effect #(do)
                                            :next-state :find-account}]
                     :find-account [{:valid-when [#(k/valid? (str config-dir "account.url") options)]
                                     :side-effect #(do)
                                     :next-state :find-authorization}
                                    {:valid-when []
                                     :side-effect #(register options)
                                     :next-state :find-account}]}
        sm (state-machine state-table :find-certificate)]
    (target-state sm)))

(defn renew [{domain :domain config-dir :config-dir :as options}]
  (if (k/valid? (str config-dir domain "/authorization." domain ".uri") options)
    (request options)
    (do (authorize options)
        (h/run-hooks :before-challenge options)
        (accept-challenges options)
        (request options)))
  (h/run-hooks :after-request options))

