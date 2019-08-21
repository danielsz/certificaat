(ns certificaat.core-test
  (:require [certificaat.core :as sut]
            [clojure.test :refer [deftest is]]))

(deftest addition
  (is (= 7 (+ 3 4))))
  (is (= 4 (+ 2 2)))
