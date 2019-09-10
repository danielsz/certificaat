(ns certificaat.util.tentoonstelling
  (:require [clojure.tools.logging :as log]
            [clojure.string :as str])
  (:import [javax.swing JOptionPane]
           [java.awt GraphicsEnvironment]))

(defmulti show-tos (fn [title tos] (GraphicsEnvironment/isHeadless)))
(defmethod show-tos true [title tos] (println tos))
(defmethod show-tos false [title tos] (JOptionPane/showMessageDialog nil tos title JOptionPane/INFORMATION_MESSAGE))

(defmulti confirm-dialog (fn [title message] (GraphicsEnvironment/isHeadless)))
(defmethod confirm-dialog true [title message] (let [_ (println (str message " " title " (Please type Yes or No)"))
                                                     option (read-line)]
                                                 (when (not= (.startsWith (str/lower-case option) "y"))
                                                   (throw (Exception. "User did not confirm")))))
(defmethod confirm-dialog false [title message] (let [option (JOptionPane/showConfirmDialog nil message title JOptionPane/OK_CANCEL_OPTION)]
                                              (when (= option JOptionPane/CANCEL_OPTION)
                                                (throw (Exception. "User did not confirm")))))
