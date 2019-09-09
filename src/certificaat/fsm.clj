(ns certificaat.fsm
  (:require [golem.stack :refer [state-machine update-state target-state]]
            [certificaat.utils :refer [exit error-msg]]
            [certificaat.kung-fu :as k]
            [certificaat.util.configuration :as config]
            [certificaat.hooks :as hooks]
            [clojure.core.async :refer [<!!]]
            [clojure.java.io :as io]
            [clojure.tools.logging :as log])
  (:import clojure.lang.ExceptionInfo
           (org.shredzone.acme4j.exception AcmeServerException AcmeUnauthorizedException AcmeRateLimitedException)
           org.shredzone.acme4j.Status))


(defn run [{config-dir :config-dir domain :domain :as options}]
  (let [state-table {:find-certificate [{:valid-when [#(k/valid? (str config-dir domain "/certificate.url") options)]
                                         :side-effect #(exit 0 "Nothing left to do at this point in time.")
                                         :next-state nil}
                                        {:valid-when [#(k/valid? (str config-dir domain "/order.url") options)]
                                         :side-effect #(k/get-certificate options)
                                         :next-state :find-certificate}
                                        {:valid-when []
                                         :side-effect #(do)
                                         :next-state :find-authorizations}]                     
                     :find-authorizations [{:valid-when [#(k/pending? (str config-dir domain "/authorization." domain ".url") options)]
                                            :side-effect #(do (k/challenge options)
                                                              (hooks/run :before-challenge options)
                                                              (k/accept-challenges options))
                                            :next-state :find-authorizations}
                                           {:valid-when [#(k/valid? (str config-dir domain "/authorization." domain ".url") options)]
                                            :side-effect #(k/finalize-order)
                                            :next-state nil}
                                           {:valid-when [#(k/invalid? (str config-dir domain "/authorization." domain ".url") options)]
                                            :side-effect #(log/warn "Authorization is invalid. Please reissue order")
                                            :next-state :find-order}
                                           {:valid-when []
                                            :side-effect #(do)
                                            :next-state :find-order}]
                     :find-order [{:valid-when [#(k/pending? (str config-dir domain "/order.url") options)]
                                   :side-effect #(k/authorize options)
                                   :next-state :find-authorizations}
                                  {:valid-when [#(k/invalid? (str config-dir domain "/order.url") options)]
                                   :side-effect #(log/warn "Order is invalid. We should delete serialized order")
                                   :next-state nil}
                                  {:valid-when []
                                   :side-effect #(do)
                                   :next-state :find-account}]
                     :find-account [{:valid-when [#(k/valid? (str config-dir domain "/account.url") options)]
                                     :side-effect #(do) 
                                     :next-state :find-order}
                                    {:valid-when []
                                     :side-effect #(do
                                                     (config/setup options)
                                                     (k/account options)
                                                     (k/order options))
                                     :next-state :find-order}]}
        sm (state-machine state-table :find-certificate)]
    (target-state sm)))


