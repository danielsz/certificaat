(ns certificaat.fsm
  (:require [golem.stack :refer [state-machine target-state]]
            [certificaat.utils :refer [exit]]
            [certificaat.kung-fu :as k]
            [certificaat.util.configuration :as config]
            [certificaat.hooks :as hooks]
            [clojure.tools.logging :as log])
  (:import clojure.lang.ExceptionInfo
           (org.shredzone.acme4j.exception AcmeServerException AcmeUnauthorizedException AcmeRateLimitedException)
           org.shredzone.acme4j.Status))


(defn run [{config-dir :config-dir domain :domain :as options}]
  (let [state-table {:find-certificate [{:valid-when [#(k/valid? (str config-dir domain "/order.url") options)]
                                         :side-effect #(do (k/get-certificate options)
                                                           (config/cleanup! options)
                                                           (hooks/run :after-request options)
                                                           (exit 0 "All done."))
                                         :next-state nil}
                                        {:valid-when []
                                         :side-effect #(do)
                                         :next-state :find-account}]
                     :find-authorizations [{:valid-when [#(k/any-auth-pending? options)]
                                            :side-effect #(do (k/challenge options)
                                                              (hooks/run :before-challenge options)
                                                              (if (k/hooks-enabled? (select-keys (:plugins options) [:webroot :httpd]))
                                                                (k/accept-challenges options)
                                                                (exit 0 "Are you ready to accept the challenges? Please enable a plugin.")))
                                            :next-state :find-authorizations}
                                           {:valid-when [#(k/all-auth-valid? options)]
                                            :side-effect #(do)
                                            :next-state :find-order}
                                           {:valid-when [#(k/invalid? (str config-dir domain "/authorization." domain ".url") options)]
                                            :side-effect #(log/warn "Authorization is invalid. Please reissue order")
                                            :next-state :find-order}
                                           {:valid-when []
                                            :side-effect #(do)
                                            :next-state :find-order}]
                     :find-order [{:valid-when [#(k/pending? (str config-dir domain "/order.url") options)]
                                   :side-effect #(k/authorize options)
                                   :next-state :find-authorizations}
                                  {:valid-when [#(k/ready? (str config-dir domain "/order.url") options)]
                                   :side-effect #(k/finalize-order options)
                                   :next-state :find-certificate}
                                  {:valid-when [#(k/invalid? (str config-dir domain "/order.url") options)]
                                   :side-effect #(log/warn "Order is invalid. We should delete serialized order")
                                   :next-state nil}
                                  {:valid-when []
                                   :side-effect #(do)
                                   :next-state :find-account}]
                     :find-account [{:valid-when [#(k/valid? (k/account-path options) options)]
                                     :side-effect #(k/order options) 
                                     :next-state :find-order}]}
        sm (state-machine state-table :find-certificate)]
    (target-state sm)))
