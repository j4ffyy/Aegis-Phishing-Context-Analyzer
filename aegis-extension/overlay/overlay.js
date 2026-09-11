/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Overlay Controller
 */

(function () {
  'use strict';

  if (window.__AEGIS_OVERLAY_LOADED__) {
    return;
  }
  window.__AEGIS_OVERLAY_LOADED__ = true;

  const LOG_PREFIX = '[Aegis::Overlay]';
  let currentEmailContext = null;

  function injectOverlayDOM() {
    if (document.getElementById('aegis-overlay-root')) {
      return;
    }

    const root = document.createElement('div');
    root.id = 'aegis-overlay-root';
    root.className = 'aegis-overlay-root';

    // Inline base64 data URI to guarantee loading under Gmail CSP (chrome-extension:// is blocked by Gmail)
    const iconUrl = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAABW5ElEQVR42u19d3xUZfb+uW1aZiaTTHpPSEgCgQRCSQDpBFgFBMEKdgFRQV0LKi4qdlT0a0EUBRRBKYJKkyKCIDX0EhICIb2XmZRpd57fH3Pvuwm6+9td3V1duZ/PfJQQ7p37lnOe85znnJfoD3jNnTuXJyJ68skns+bOndu9/c+uXH+MSyQi6tu37/x+/fo9RESc+rMr1x/j4rRaLYWHhx+PjY39RhRFIiLhyrD8ccw/N3v27ESj0c8dEBBQv3v37mAiIgDclRH6378EjuMoMzPzRUEQoNFoMGTIwKntXcOV63979/NnzpyxWiyWqvDwcG9wcDBCQoJPA9AQEa/ggSvX/+glCYJAffr0eY2IMHXqVM+NN97oISIMHDhwBhFRZmamdGWY/kcnn4jolltuGWyx+LuJSF6/fr134cKFXiKSg4KCGubMmdP1yiL4HSL6v2e2FbMvEBFNmzYtPTAwsIzjOMTExMgVFZU4e/YsAgMDZUEQEBIScua1116LVrHC/4cbuOIq/su+XLwsdOOISJw0aZJw+eTodDoaNWrUxMDAwBqe50FE8rvvvgu73Q673Y45c+aAiGSe5xESEnLhtttuG6XRaH5uwtVntr+/QETilQjiP7fb2aSLokgGg4EAiFqtlni+w4aVAPCTJ08eGh8fv0Ov10MURWi1Wvmhhx5CQ0MDysvLUVFRgerqatxyyy0QRVEWRRF+fn7o1KnTN/fcc09vZbExl8DzPOl0OgIg6vV6EoQO9IHwe7MM/O/su0IURXnevHmdBgwYMDM6OnplcHDwwfj4+COhoaHbkpOTF4waNWoiABPHcW6O47w8z3uICF6vl4hIFkWRHzx4MGk0GgJAsiyT0WikqwYOJCLiOI6DLMvE83ybIAieZ5991isIgvvrr78OGjRo0JTExMT3Q0JCdsfHxx8LDg7+MS4u7uPBgwfftXjx4gie52Uiwu9sXH8fsTsR0YoVKyIyMjI+MJlMTZIkgeM4CILQ4b86nQ6hoaEF/fr1ewyAgYhIr9fToEGDZptMJhCRx2q14vTp06iurkZDQwP27NkDSZK8ROQ1m80to0aNmqiwg7Rq1aqwzMzM+QEBAaWSJIHneeV5PHje9xFFEUFBQVWZmZnPqc/8w+UW/l0+UB3IGTNmDAgLC7vAcRy0Wi2sVmtpUlLS1127dn0jPj7+2bS0tGUxMTE/WCwWG8/zkCQJsbGxh2fMmNFXdRfZ2f2f1uv1ICLPtGnT0NbWhqamJowdOxZEJJtMRowePfpm9dnjx48fGxoaWqROstVqrenUqdOOlJSUhZ06dXomLS3tvU6dOm0KDAyskSQJRITY2NgDL730Uty/cxH8lvGG8G+a/K7BwcENRASrNah4+PDh965atSq4vf/leZ4kSaIHZ89O6N+//7NhYWFlRASz2dx44403DlXBYGxs7Pc8zyMiIsJTVlaGo0ePwmAweARBQJcuXRaLokgcx9GwYcNu0+v1MsdxCAsLO56dnT3jzTffDJUkiTjON/4cx5EgCPTuu69F9+7de7a/v38jxxFCQ0NPL1myJEzBA/yvjIF+e5Zl0aJF0tq1a0PUufiVVj5HRBwAfXR09BEiQnR09LGFCxfGEREJgkA33XRTn169ej2SmZn5Yp8+vR4cM2ZMllarVb9TTEpKymeSJMFqtTbOmjUrQ+EBrvL395eJyLthwwZ89NFHXiLyhoSE2OfPnx9PRHTdddddYzKZvAaDAT169HgVgJ+y8/jhw4cP69mz56M9evR4MTs7e+bUqVNT1C88Y8aMvhaLpYSI0KVLl3VKJMH/mpuB4zh65513Ynfu3Pmboa15AGK/fv0+HjBgwFR1ApSQifulKdvs7OwZkiQhMDCw9sUXX+xMRPTll19aU1NTPzObzV6tVguNRgOdTguj0YjIyMjcESNGTOJ5njQaDfXr1+9RnucRHh6+D4AEgI+JiTlIRHjllZflhx9+2E1ESE1NXc3zPK1duzYkICCgTKvVeq699trJgiCQJEk0YMCAB8LCwvL8/Pzw12fq4O/v35qenv4iAIGI6Kabbhrp5+fn0Ol0GD9+/FAiIiU0/aUhLxkMBurVq9e8fv36vQ+A/7dZg3/Gx6gvN2LEiNH+/v5ITk5e+umnn0apZpKIxH/BInDKwuKjo6P3EZG3R48e8zmOIwBc9+7dPxRFEYIguDQajVOSJLcoim5RFL08z0Ov16Nnz54LAWh4nqdevXo9aTKZMGzYsFuJiHr37v0KEWHixInuQYMGeYgIgwYNupuIqGfPnnNNJhNGjBhxIxHRzp07LUlJSeu0Wo0K+GRJktzKx8HzvKzX65GdnT1r7ty5vEajoU6dOm0gInTt2nWJMpbivzjxgmrtZs2alREVFfVtYGAgbr311j7/7ML6V6wyT0TCP7gYeK1WSzExMVt5nkdgYGBFnz59Hqmvr/dvtxB4dTH8jXty7V5aIiJ67733Qsxmc6PBYMC1116bQ0TcG2+8EW6xWOqVCYcC+LwajQYajQSNRiMLguDWarXIyMhYAoDTarWUkJCwKjw8/LgoijRkyJDrOY5D586dPfHx8V6NRoNJkyZlAuCDg0Mr09PT5/M8TxUVFX4JCQnbRFGEJIlujUYjS5IESZKgLjZBECAIgicoKOgkAImIuL59+86UJAlhYWFH21vESZMmqezi5e/PAeDa7XZOnfjFixfHpqWlLbBYLC3Kd17+j7qWdovvH7fEmzZt0j7yyCOdJKkDHS5MmjTpby4GdSXedtttWX5+fi4igk6nQ2Bg4IX+/fvPWbJkSVy7gbh8kf1kQERRJADahx9+eIDBoPeYzWZMnTo1W/Ht4QEBAc2iKCItLW1HTEzMLmVSvOrkaDQaryAILq1Wi5EjR95ORPTiiy9au3Tpsnf69OkhEyZMSNLpdF5/f38YjUaYTKbWo0ePWkaPHt0tLS1tFwCR53nq06fPS8o9nRqNBu0mHzqdDikpKV8nJSXtIyKEhIScVhfAkCFDpkiShJCQkNIdO3Z0AiBeRhi1B3Q/mUi9Xk9PPvlkz+7du78dEBBQr0QY3qCgoKZXX321U7vN8vfIMvZArVZLc+bMST516pTmH/LngwYNeis2NnZ7Tk7ODcXFxYFqTPz/WQyCIAjUrVu395VBcmi1WhAR9Hq9PSkpaX1OTs49TzzxRBcAJp1ORxqNhrRaLWm1WgKgeemll+JGjRp1S0pKyiehoaH5FoulQZJEt06nxdChQ29Ud0qPHj1eMJvN7uzs7EfMZjOFhoYeEwQeGo3EdqgkSbIgCHJQUFDV3LlzY4iI7rvvvpHvvvtu9ODBg0caDAZIkiSLoiibTCbHLbfc0mXu3CczZs6cOUBZzJkWi6VNEASPRqPxtruvRxRFJCYmrvX396eePXsu9Pf3dw0dOvR2nueJ4zjq3r37C6IoQKvVuqxWa0NERMSpLl1S373mmmuuXbhwYSQArVarJY1GQxqNhvR6PRUXFwfee++9mYMHD34sPj5+lyiKsrqRJElq02q1yM7O/jPP8z8x/cpcCJezpBs2bAgbNmzYnbGxsXsHDx68QMEp/P/P99LOnTstoaGhl9RVnJaW9uHNN988HIDhMrqVV02b8qV4AObo6OhzHMehb9++rhkzZngiIiKgMGSQJMkdHBxcGh0dvT85ufPWlJSUbTExMTvDw8PzLRZLi0rZquZVkiSPIAiIi4vbrlgRXhRFuvvuu7v+6U9/CiMiSklJ+UgUeSh+WZ0oL8/zsslkcs2YMaOrOmibN28ODwgIKBVF0UtEso8dFBAaGpqraAIEIuJGjRqVYzAYIIpi+3tCkiS3RqPBgAEDHiMibsKECbEPPPBAF0Hg1ckwhoSEFCnf3asSRqIowmAwICDAYouICC+IiYnZ1blz560JCQnbwsPDjwYEBFQpeQoo+AGPPPKIJyUlxcVxHLp06bJJnei5c+fyyvt0MO+CIBAA85gxY8YlJyd/arVaq0RRRGhoaPG2bdv8/6Eklmpa5s59oUtgYGCDMmkwGAwIDg4u7Nmz5/9dd911ow8fPhx0mZtQeQD+tttuywoKCmohItx6663eS5cueb/88kvPlClTPKmpqVDImA4fjvM9R6fTenQ6nUer1coajcarmF5Zq9WiR48ec/R6fYcHnjhxItRqtV663AKIos9y9O3bd6ayaHkApujo6D0ajQZEJF977bUYMGAAiEjW6XTo3LnzZ8oiEyRJooyMjA98/l9ytXMvsiAIiIiI2K8smPY7UZecnPSFKIrQaCTZh0s0Xp1OJ+t0OrdOp5MlSfzJuyt8BTIzMzFt2jT3zp07PadOn8LQoUNlJfw98+mnn4b/nD/XarW0du3a8D/96U8T0tLSPgwMtBRrtRqIou85FovF/uSTT2b8U0BQ3S3jxo271mg0unmedxoMBtlgMICIwPM8QkNDq5OSktb169fv0RtuuOGqr7/eGaTX60l1F7fddlt/k9lUSUTygAH9vQUFBQCAyspK76FDh+RVq1Z5nnrqKc/YsWM9nTp18uh0OpmIvO0HRZVsabVaaLVa2WAwIC4ubtvAgQNvnTx58tDBQwdPCw0NPaPutnaT7xIEASkpKUtU7AFAio+PX6e4JXdsbCzKyspw6NAhmEwmCILg0Wq16Nat2+sKyOIAGGNiYn5UgGYH6yJJEqKiovbk5OTcesMNNwzLzMy8Nyws7KhO5/uuGo1vEjiOu3yyvWazWU5PT/dMnjzZ8+KLL3q++eYb+fjx497GxkYvAOzavQvx8fFeIkJERMQZAIFERJIkEQB+6dKlkWPHjh2elZU1NzExcXtQUFADR77n+Pv7IzAw0MPzvNNoNHrHjBlzPcdxfzNi+HvmQOQ4zjN8+PD79u3b944sy/JNN91EVqsVq1ev5ouKivj2oMVsNtfq9foLOp3ulNlsLg4ICDhqMpn67v5h9xPVVdXk7+/PPfXUU3T33XeTxWIhp9NJHo+HZFkmm81GJSUldPLkSTp9+jTl5eVRYWEh1dTUUEtLCymJHFIWBRcYGEiyLFNrawu5XG4SBAFqIsfr9XqISEpISNh07ty58RzHuQAYExMTVxYXF1/j8Xg8ZrNZ3LBhA3Xp0oUkSaJvvvmGJk+eTIIgeERRFBMSEt46ffr0QxzH4bXXXot+7bXXNlZXV3cTBMGjjAsBgNfr5TQaiXQ6PfE8T42NjSTLslf1s1qtlkwmE4WFhVFiYidKSUml9PR0SkpKovDwMDKb/UkQBOI4jjQaDZWWltKbb75J//fWW5C9XoqJibHl5OQ8lZeX1+pwODrb7fY4h8OR1traGmOz2cxOp5NNVnJysnfS9dejpqaaVq5YSR6PR+jXr99D33333Zter1ckIs+/RMaIokgjRox42Gg0QhAE70MPPSSXlpZi48aN3unTp3t69OjhNhqN3stNmlarhZ+fH/toND6uPCsrC4sWLUJh4Xm0trbC7XbD6XTC6XRClmV4vV60tLSguLgYubm52Lp1K9auXYvVa1bj8y8+x7znnvMMGDDAYzQavaIoerRaX2im0WhknhdkjUaD5OTkLwAYiYiee+655PDw8B+Vne8xm83YvHkz7HY7amtrUV1djdbWVrz//vtqUsmj0+nQqVOntapaeN68edGxsbHHBEGAKIoeNRzUaDQeURQ9RqPRO2TIEM8rr7wir1mzBhs3bsS3336L3bt349SpU6iqqoLT6QQAyLIMl8sFl8sFp9OBpqZGnDlzBi+//DISExMV0KyDXq+DyWSSVUx0+fgGBFjk7Ows94MPPuj57rvvvBUVFXjyySdlnue9BoMBAwYMeFixxiL9QlWLIIqiPGzYsNv379//YVNTk9inTx/5gw8WCenpGdTQ0EAFBQV08uRJnDx50ltQUIDz589TRUUFZ7fb/yZRYTIZaeDAgdSzZybFxsZSeHg4WSwW0mq1pDfoyeJvIX9/f/Lz86Pm5mbatm0bffLJJ7Rr1y5qaGgglbPnOA4AZI/HIxqNRkpOTn7lxIkTs71eLw0fPvzGQ4cOvW2324NcLpccHh4ufPrpp9SnTx8iIjp27BiZzWaKjY0lrVZLq1evpunTp1NbW5us1WqFgICA/MGDB9+7atWq7yoqKowDBw78oKSk5CaHw0GKNRA4juO8Xi95PB6yWCzUr19/uv322ygnJ4f8/f2pubmZbDYbNTQ0kN1uo5aWVrLZbFRRUUl5eWfpwIH9dPhwbnsrd3loRRaLRQ4PD0dSUhKXkpLCpaencykpKVxcXBz5+/vTsWNHafr0e+UDBw4IJpPJm5WVNXPnzp3vejweQQG6v1jWJHAcJ0+cOHHE3r17l5aXl0fodFp51qwH+RkzZnBRUVHkdrtJlmXyer3U0NBAtbW1VFtbS+Xl5VReXq4MgJ1cLhfJskyyLJPb7SZJkigoKIhiYmIoJiaGoqOjKTY2lsxmM+Xn59O6deto5cqVlJ+fz5I+ysr2KjtKEEWRgoOD8/v06XP/hg0btv3lL3+JX758+QtlZWU3tba2ktfrlbOysoRFixZRbGws8TxP+fn5lJOTQ5GRkbRlyxbSarWk0+lo//79NHXqVLpw4YIsSaJgMPjJCQkJ7yxbtuzZ3r17N2RlZd1x6tSpF5uamsIAkCDwHiJO4DiOc7vdbCITEzvRDTfcSBMmTKDk5GSy2Zro0qVLVFZWRuXlFVReXkZ1dfXk9XqJ53nieZ44nie9TkdGo5Gs1iAKCwulsLAwCg4OpsDAQDIYDCQIAomiSKIoUnFxMb333nvet99+G06nUwgJCans16/fnV999dVmJeST6dcup1q8eHFscnLyBgVJo1OnTvJrr72GCxcuoKWlBQ0NDaiqqkJNTQ0aGhpgs9lgt9vR0tKClpYWJsNqaWlBW1sb3G432l+lpaVYuXIlJk6cCH9/f2bydDotdDqdVzW7PM9Do9EgMDCwukePHo/7+/sTAKFXr15/CQ4OrleRviiK3lmzZqGqqgq1tbVobW3F999/j7CwMKhhV0ZGBvLy8tDU1ISGhgZcuHABN9xwA5QBhE6nQ1hY2KV+/frdYzQaCYC+S5cu8wMCApo1GkYRezQajUen03l1Oh373iaTCWPGjMFHH32EixcvdnhXr9cLl8uF1tbWDmPU0tKC5uZmNDY2or6+HjU1NaipqYHNZkNzczPOnDmDefPmIS4uTlbdbVJS0uZ58+bF/7vrGwQV9A0bNmxqVFRUiYpsY2NjMWPGDKxfvx4XL15kL6ROuM1mYy+gvmRDQwNKSkqwf/9+vPPOO7juuusQGRnZIQrQ6/VerVbrkSTRIwg+bkCn08FqtV7o2bPnIwD0ALQZGRkzQ0NDi9qFmJ5+/fphy5YtaGlpQU1NDdra2vDxxx/DaDSC40iljkFEiIuLw7Zt2+BwOFBdXQ2bzYZPP/0UycnJUAAU/Pz8EB0ddbp///63BgQEEIDAjIyMeYGBgWU6nQ5KfgI+bKL16PV6WRAEho9CQkIwZswYvPjiC9i6dSsKCwtRU1ODpqYmNi7Nzc3so45TXV0dzpw5g+XLl2Py5MkIDQ2BGjFFRERcGDJkyD3twmPhn026/NNJimeffRZEhGPHjoVMmjTpk0uXLuW4XC6v+vD4+HhKTU2lTp06UUREBFmtgSQIAnm9IIfDQfX19VRVVUlFRZfowoULdOnSJWpra4OK9JUdRB6PR/B6vSzvrtVqW61W65bevXsvW7Vq1Y6lSz+IfvPN9+6urKy81WazBbe1tRERyV26dOFnzpzJXXfddSSKIvE8T83NzfT888/TwoULSZJE8npBKSkp5HA46NKlS+TxeEin09GcOXNoxowZ7JlNTU308ccf04cffugtLS0FEQlGox+Zzf6XgoODF7/66quf5eTk1E2YMGHYiRMnJtfW1o5wOp0mj8dDgJc4jieFdPI6nU5OIXM4SZIoPDyci4yMpISEBIqMjCR/fzNptTriOI6cTifZbDYqLy+n/Px8On/+PNXW1qo6BK9Go+Hj4uIW7t27d3ZQUJCtnTra+59KA2uIiLp167bQR3xo3D70qv9ZouPvfVRzrtFoIAjCZcxZQGFiYuIno0ePvmHHjh3J69ev7zJ48OAZsbExP1gslvb38fTu3VteuHAhysrKYLfb0dDQALvdjjVr1iA1NZVFJyqf8dRTT+HWW28FEUFh/aBkBrF7925mpZqbm1FQkI8XXngeyckpsmoROI5DQEAAOnXqtGP48OF3bNu2LSEvLy/++uuvvzY1NfX/goKCjvn5+TlUTkDhK+D7s/BPjZEgCDAYDCo17NZoNOjbt+9MlQ/6JaKLf9kdAPDGxsYuKS8vv43jOA8RiW63mziOI4PBQBzHkdfrJQAqGUPtsoOkug+O4xwajaZFkqQ6g8FQbrVaCyIjw88nJSUXBAcHN585cyb4zJkzvSorK4fabLaedrud3SA8PNwzbNgw4brrruOys7PJaDSSajWOHDlCCxYsoPXr1zO+QpY9BBC53W7av38/FRUV0Y033qjmI4jneXI4HKTVaunOO++kGTNmUEJCAnk8HhJFkWpqamn37l20du1a7w8//OCtr68XVaGGn5+f12w254aHh+/o3Lnz4aysrAqbzaY7depUWHl5eXJNTU28zWaL8Xg8YW632yLLsl5JIEkARACkfpQIhziOI4/HQw6Hg1QySFmAYlxc3HMFBQXPKJbX859eALxGo/EmJCRsys8/N1oQBFkQRCE7O5vOnj1LlZWVl8m1RJIkDVmtVgQFBXFarbbe7XafMRqNDo1Gc0mSpEYAfHNzs7elpcVSV1cX1dDQ0KmlpSXO7XaL7e+VkJDgyc7O5oYMGSL069ePIiMjVR6cXC4X5ebm0kcffUxr164hl8tFKhvo9XpJEARyOBw0ceJEWrp0KdlsNho7dizl5uaSVqslWZZJEAQWpQQGBtKUKVNoypQp1LlzZ4bYnU4nlZSU0N69e7F9+3bvwYMHqaSkRLicptXr9aUmk6nQ399cZjKZmwwGQwvP8xKAIK/Xa3W5XIbW1tYoIkpobGxETU0N19bWRh5Px/lMT0+niIgI2rZtG3Ec5wEgJicnLzh79uzDXq/3X0b8v2gBaLVab0xM3PbCwvxhPC/IoigK+/btI6vVSlu2bKF9+/bR0aNH6eLFi9TU1PSTdLXy+ZuVPaIoUGCglWJiYuSuXbsiPT2dT09P55KSkriAgADSaDSkxuCVlZW0a9cu+vzzz2nnzp0kyzJJkkiCIP7E8jgcDho9ejR98cUX1NLSQqP/9Cc6dvQo6XS69rw+m2iv10tGo5FGjx5NkyZNor59+5LVamUsnsPhoJqaGrp48SKOHj2KkydPevPy8rji4mKhvr7+J5P5/zWtgkAhIcGUkpJKWVlZ1L9/fxo0aBDt27ePcnJySKvVemRZFrt06bLs9OnTt8uy/C8vgF8cLsiyGxzHExFIEATyeGQym810880301133cW4gIsXL9KFCxeoqqqK6uvrqampiXM6nRzP8ySIAgx6A1ksFm+gNZACAwIpLCyMIiIieCUGFkwmEzPTPhq4lYqLi+no0SO0bdt22rFjB5WWljIz6ftd3+JwuztOgJ+fH23evJlyjxyhgvx8Onb0KPn7+/9kkWo0GtLpfNajra2NVq9eTatXr6akpCQaMWIEDRs2lLp1606hoaEUGxtL8fHx3ODBgzlZ9vA2m53q6uqouroapaWlqK6uRmNjI9XV1VFjYyM5nU5OlmWOiCM/PwNnsfhTUFAwRUREMFAYGhpK/v7+pLq81tZWtjiVhez9VWL7XyAdU4gPEMARz/MkCDzJskyNjU3U0tJMUVFRlJGRQRkZGezfud1ucrvdjNTxer2cIAg+QcFll9vtJqfTSfX19VRdXU0XL16ko0eP0qFDh+jo0aNUXV1N7UvAeJ4nr9fLBovneUpOTqY+ffpQRkYGXXXVVbRw4UJaunQpnT9fQJcuXSKO4+jxxx+nQYMG0Z49e+jw4cN0+PAhunixiFwu370NBj0RcSTLMhUUFFBBQQG99957FBUVRZmZmdSrVy/q3r07xcXFUXBwMJlMRgoMTKLU1NQOFs7r9TLyR5ZlcrlcpOoO27++LMtkt9vp7NmzZDKZKCAggHR63eWbj/6rC0Ad4PYWHADpdDoqKCigcePGUZcuXahHjx7UuXNnSkhIoIAAC1ksFjIazSTLHrLZbL4F4XKR0+XyUadNTVRbV0vV1dVUUVFJpaUldPFiEZWWlnbYpRzHkVarIZ8F8nkVdeITExNp/PjxdO2111LPnj1Jp9NRc3MzVVRU0OHDhwkApXVNI4H3YYdDhw7R7bffzn63paWF9u7dS6tXr6ZvvvmGqqqqFCCpI61WqwBcUGlpKZWWltJXX31FRESBgYGkhnZRUVEUFhZGoaGhZLVayWQykZ+fgQwGPxIEngRBJIvFoiSSGqipyUZNTU1UVFRE+fn5dPjwYSopKaENGzZQSEgIwYsOY+/9jwV8f0cHmJSUtF3VxZlMRhw5cgTNzc3Yt28fI1kuI3Zwxx13wOPxIDc3F1FRUQgICIC/vz/0ev3PpU87hItarRZ6vR46nQ6qTKs989azZ08sXrwYTU1NAICCggK8+eabGDduHBISEliYarFYcPHiRWzduhUcx0EURRiNRnTpkoopU6Zg+fLlqKurAwBUV1fjxRdfRGxsLMhXnqaGY0wdrNfrodFo/r/f32AwwGKxwGw2oWvXriguLobT6cT48ddCp9OhvSjEl/QJwNmzZ9Ha2orNmzcroazGLYoikpKSPlasxn+lvxGv0WgoJSVlk6Le8ZhMRuTm5sJut+PIkVxYLP4QRQH+/v4ICwtjgz9y5EjIsoz9+/dDlY2Josg+ZrMZ/v7+HSZblWK3V+eoWgEiQlRUFN555x24XC4AwObNmzFhwgSYzeYOA6pmJdPS0lBfX4/Tp08jICBA4R46xuaRkZF44IEHcOrUKQBAQ0MDZs+ezXgEdRH83HdSF4VWq4HZbIafnx97PyV9jcjISBQXF8PhcKBPnz6MpwgNDYXFYoEgCIiKisL58+fR3NyMLVs2K+/gWwBpaWlLf+kC+CW6cs7j8VBra2ulgoYBEHkVMyVJGpIkDXk8Mg0Y0J8OHDhIe/bsoe+++47mzJlDbW1tLLGh+j+NRkOyLFPfvn1p5MiR5HQ6ieM4lmRSwY/qerxeLzmdTrrpppvoxx9/pPvuu49++OEHGjFiBI0ePZq+/PJLamlpIZ1ORzqdz3QLgs/rdenShbQ6HVksFoqNjSWv10uiKKmhG+l0WiorK6O3336bevfuTXfddRc1NjbSSy+9RLt376a+ffuSw+EgVQd4OS6SZVlh9Fx0yy23UFxcHAFgiRyO45T35snpdNH8+fNp586d9OOPP9KuXbspKSmJZFkmnU6nxv5sbNs9y9Z+TP7j1cEcx5HJZOLVL+HL8nkIABM8EhE5nS4KDw8jWZZJo9GQxWIht9tNGo2GxdyAz38DoOnTp9MDDzzQAfleHia53S4SRZHeeustWrFiBWl1Wpo2bRrl5OTQ9u3bFQSvY/dvj56JiLp07UpeWSaTyURdu3a9zLd6SZa9TLDpdrvp448/pt69e9Mbb7xBmZmZtGfPHrr33ntJFWVcRnAxIGo2m+mxxx6jyZOnkCzLjNBRv4saQQUEBDAQGBYWykJHvV7PxtHtdrNnKSCyTsk+/ldqBQWe5yktLe1NSfLp5kVRxO7du9HU1IRLly4hKSkJRITs7Gw4nU6MGDECRISBgwaizdGGM2fOwGKxgOc56PV69OjRAwsXLkR9fT0aGxvxySefICsrC4qCF5IkQqfzmXyr1YpNmzYBAL77bgc6d+6smsd2ptn3+1qtpl1W0YcXVq5cicbGRjQ3N+OZZ55hdHD739NqNfC9mwS9Xs/8c05ODkpKSgAAr776KjiOU8z/X12B2WzGqFGjsHXrVthsNlRWVuL5efOQnJzM3Fbnzp1ZMqh79+4gIkyZMgUtLS3sfbKzs1FbWwu73Y7Vq1erbsKt0WjQs2fPR34pmP9FLkBZfZUcxxPH8aS4BAWda8loNBIRUUtLC8myTMEhIcRxHLW2tJLb5WZWAvCt6r59+9LYsWPJ6/WSy+WikSNH0lVXXcV0hoIgkNPpouDgYPr6669p9OjR9OGHH9Kf/nQ15efnk5oRU+r7iecFcjic5HS6aPTo0TRt2jRyu91kMpkYvSvLMqWlpTHa+uGHH6aePXuSw+Egp9PFyB6VCtbr9bR161a66qqr6Mcff6RHH32UFi1apFgZ384EQEajkUaOHElZWVnU3NxMOp2OJlx3XQdrYzAYSKfTks1mI7u9mTiOo+joaGpra2Oxv8lkYt9BSXb50hA8RxqNpua/3iDCYDBU+zhrnxlqaWlhJIrFYiEioubmZgJA/mYzAaDm5mZqa2tjvlkld95//33Kzs6m6upqcrvdNHz4cJo/fz61tbURz/Pk8fiaOaxZs4b69etH8+fPp6lTpyqZPC15PG4i4pSF4iSn00n9+/enL774gtatW0f1DQ0kyzJFRkZSTEwMuVwucrvdlJycTP7+/uRwOEin09EPP/xAb7/9NiUmJpLD4SSXy0WiKBARyOPxkF6vp6KiIrr66qvp22+/pXvuuYfeeutNcrlczDxXVVXRQw89RDfeeCNZLBY6eOgg9e7dm7788kvmLiRJIknSUGtrK7W0+MYoMDCQWlpa2GQHBVnVQhlqbm5mm4/neDKbzXWKiBf/8QWgPtRisVT7fJfvrex2O3EcR6IoUlBQkGIBfBMeEuIrILbZbGSz2Uiv15PBYGA+0c/PQMXFxfTBBx/QJ58so5MnT5Kfnx8pIkySZZk+/vhjGjhwIL39zjv02GOPkUajIVEUSJZ9CSCXy0kOh4PS09Pp008/pfXr19P48eMpPz+ftn77LRERdUpMJEXYQR6PhwICAig8PJyIiNasWUOtra1099130/bt2+nll1+myMhIamtzkMvlZr5Yr9dTU1MTXX/99fT999/T/fc/QI8++igDhoIgkF6vp02bNtH69evpjdffoJaWFva+qgXQaDRks9nY5IaHh1NdXR3DPmFh4cyqNDY2KWNFnCCIFBQU1PBftwChoaF1CnjhiIhqa2vZLggMDCQioqYmG1VWVVJ8fDxbAI2NjWQwGNiAcBxHbrebBEGgNWvW0OLFHylgz61MrItmz55NEydOpPXr19OsWbNYksfhcDK9QXp6Oi1atIg2b95M1113HbW1tZHD4aADBw8wEimta1dVYk0ej4f8/f2ZaS4uLqZjx45Ra2sr6XQ6evDBB2nbtm307LPPUkxMDKu6aWtrI61WS3a7nW666SbKz8+nl156iYYNG8YWgZpYevbZZ+nQoYPsfdTLbDYTx3FUV1fHdnxkVBRVVlaSS6EgIyIiGHNYWVmh5lA4nufcAQEBNUpE85+3AOpDY2JiKnmeb1MWAKqrq5mJi4iIUPIDHqquqaHQsFCG7Ovr60mr1ZKfn5+yAIgAX3hXUVFBFy9eZCGW0+mkPn360LPPPkvn8s/R1KlTiVfCQ5PJRMnJyeRwOIjjiPz9/SkrK4vMZjPV1NSw8HLfj/vosgqaDrWIKtJ2OBz0448/kslk8n3v6mrq1KkTZWdns2SRw+GgrKws0uv1JEkSVVZW0u23304ul4sWLlxIgYGBCooH8bxA+fn51NRkY02s1IDBYvEV61RXV7PIKSgoiKqrq0kURRIEgSIjI1mUVF5ezhhPQRDqJk6cWE1EpAh0/rMLQH3ogw8+WCtJUp06oGVlZSwWjo6OJlmWyePx0Pn8AgoPCydJksjr9ZK6UNRBaB/JqPyAz9x5SavV0htvvEGCIND9991PNTU1jDtoaGigjIwMuuuuu8jt9tDu3bspMzOT3n77bQoLC2ODZ7Va2f3PnctjoaEoitTS0kJnz55lfx8VFcX+3t/fn2bOfIBycnIoPz+f3G43PffcPEpJTaXGxkbiOI70ej3t27ePnnvuOUpKSqI5c+aQx+MhnvfhhvZdRdq/a1BQMBERS2IFBARQaGgoHT9+nAFUq9VKgE9JpdDRAIg0Gk3F4MGDm/7bLoCLjo62azSacmUBeEtKSsjtdpPHI1NSUhJNnDiRpk2bRpGRkWQJCGC4QNULWK1BP5tk8iluBXK53HTzzTdT//796cMPP6Tt27eTTqdjcbIkSbRmzRqaNGkSvfnmm8ziPPXkk/T5559TYGAgtbW10ahRo9guP3++kFpbW5mv9mUsy5jVGjRoEDU2NlJQUBC98sortGjRB2yCvvpqPWVm9qSlS5awTmMej4c0Gg0tWLCAcnNz6d5776W0tDRyOp3Mf//cpeKOkpIS9myNJFFaWhrdcccdNGXKFIqOjiaPx0NOp1NNfAEAGQyGKiWc5BW38F+5BFEUKT4+fq1Swuzp3LkzysvLUVVVherqaqaAbW1tRVl5GXr06AEiwv333w8AePzxx9UK4ssoVV8Ztslkwrlz51BbW4uoqCgIgsCoVo7jGP/euXNntLa2Yv369QgLCwMRwWg04vvvv0drayvKy8vRtWtXEBFCQ0ORl5fHuoTt3LmT8QOTJk1iIs1ly5ax2D89PR25ubmor69n30PtEqZyD0SE0aNHAwCWL1/OqN3L6WL1dz/77DMAUJtU4eqrr0ZjYyPsdjsrIqmoKEdtbS1OnjypcCa8W5IkJCcnv6u4lP/qOQeiUg79hiKPdvv7++PkyZOoq6tDRUUFpk6digEDBqBv375ITU2F2WwGx3G45pprAAALF77HqmHaD5Jer2PECACoQlS9Xg9B4GE2m3H//fd3GNBHHvkzACA3Nxf9+vUDESEpKQln8/Lgcrnw+OzH1Qpl7NixA7W1tbDZbFi8eDFUjd/SpUvh9Xrxww8/QNUc3nDDDSgq8km677zzTpbYCg8Px7Tp06AUkEKViO/YsQNOpxNdunSB2tXs8nwBEeG7774DAPTs2RMcxyEoKAhpaV3Rt29fDBkyBI888giqqqrQ1NSEDRs3KkpmjUer1aJXr14zfgst7tU+PlOU7JyH4wgbN25EU1MT6uvrkZGR0SHBorZTS01NhcvlwldffcV2SnsmTZIkCIKAH3/8EXa7HTExMSwbqA7g4cOH8eGHH7L7ms0m7Nu3D62traipqcE111wDIsLQYUPR0tKCvXv3ssWydOlSOBxOeDwezJ07F+SrwkV5eTlKS0uRkpICIsLjjz+O5mY77HYbtmzZAq1Wy7J6e/fuxcdLlrCFqd57zJgxAIBXXnnlJ4vbJ3z1/fuCggLU1NQgIMCiJMQ6JqOuueYaNDc3w2azYeHCheo4yX5+fhg7duzwX9p/6BdjAJULSExMPK8kLHiAqLCwkAG5bt26qZJulsQxGo0kSRI1NjZSSEgISwKp4IjneXK73dS9e3fKzs6mNWvWUHFxcYfQLSQkhPR6Pd1+++30yiuvkNvtJpvNTs8//zwLwRYvXkyDBg2i73b4ElB9+vSh7OxsEgRBkapdoLNnz9Lx48dJEAQaM2YMWa1Wuu+++ygvL48mT76FnnlmLjU2NpHb7aG5c58hp9NJer2eli9fTtnZWRQaEkyiKJLH41ESSiJt27aN8vLy6Prrryc/Pz9yudwdWsvJspdCQkIoLCyMysrKyM/Pj0wmE9M1qBVAGRkZDAudO3dO9f+8JEltvXv3LvylISD9Ws2kPvnkk5DAwIA6ZWd6p02bxoobXnzxRd8uHDoUO3bswMGDB1FcXMwk2xcuXEBkZGQHU6nupKeeegoAMHr0aMbPq393/fXXo6WlBZcuXYLD4cBLL73ETPMbb7wBp9OJw4cP45ZbbumQ3r08397+4+fnB6vVyv48a9ZMnD5zGk6nEw89/DDDFevXr0drayuKi4tRXVOD9PR0ZsXUlPdf/vIXAMDgwYM7pI7VXMbgwYPh8XjQ2tqKuro6XLhwAT/++CO++eYbpHXrBiLCihUrYLfb0djYiOHDh4OIZKX30Em1K9kvTQSJvzAbCCLipk6dWm21Ws/b7c19iAhnzpzhnE4nSZJEKSkpSkbQSQMHDqRz587R4dzDVFNdQ126dKGePXtSeHg4lZWVsV2i1tfl5ORQdU017du3j6V/1WvChAmMVKmqqqKHH36YbDYbvfTSS/Twww+TXq+nhoYG+uyzzygnJ4eio6PJYrFQSEgIBQcHk16vZylZWZapoaGBamprqK62jhoaGun8+QJ6663/o959+tKypctowRtvkMlkoqVLl/q+lyJF02m1NHbsWDp+/DjLJxARbd68mZ555hkaOnQoff/99x0yqERE0dHRJAgC7dmzh4qKiig8PJy6detGiYmJVFdXRwq4Jq/XS01NTXThwgUWAfj5+eVLkiQrAFCm//IlKLq7D5X+ve7IyEicP38eTU1NOHjwIDQaDUwmI6qqq5m/JSLMnDkTADBu3Di2S1RUHxwcjOrqaqxbv57tLjWLlpiYiMbGRjgcDlZXV1paiubmZvz5z39mPrlz586IiIjoEI24XC7U1dWhpKQExcXFKC0tRUVFOerr6zrUKZ46dQr+/v5QTCz8/c346quv2LPUsjePx4PTp0/DYDCwhhaCIMBo9MPFixexfft2lqVUs4pEhJdffgkAkJOTw8bjs88+w/79+0FESEiIR1FREWw2G3bt3g1Jo1E7lSEzM3P2rybp+xUWAOf1eikoKOiw4ve5yspKKioqIo7jKDIykhITE8lub6a8s2dpwIABpAhAqbCwkJTqIrY7VN4/KSmJgoOCaO+eHxguUHfPNddcTadPn6a//OUv9PDDD9OuXbvYPV9++WV67rnnqK2tjfLz80mr1ZIoivTOO+9Q9+7dKT09nbp06UJdu3alrl27UmpqKqWkpFLXrmnUvXt3ysjIoK+//oYlqc6cOUNBQUG0evUauvrqq9lLr1u3ju6//3566aWXqK2tjQYOHMiykJIkUXNzCx3OPUzJyclkNpsZpa1aiC5duhIAqq6qIkEQyGj0o969e9OJkyeIiKhr1zQKCAggnufp7Jkz5Ha5iOcFXpIkUjqn/qIk0K92qSj0rrtu7WM2m6HVar1EhLfeegvNzc1oamrC9ddfDyLCO++8g9LSUibTSkvrCqfTiRUrVvzEx0+aNAler7eD/1flVlFRUSyaUMO3zMxMPP/88zhy5AgAYNWqVQgJCUFERDiampowa9Ys9ruqPs/34X6CCz744ANcKi6GRqNBl9RUJgnbvXs3Hn/8cRYhqB+j0YiIiAhW3qbu8hdffBFtbW0st6/ValmJV35+PsrKymC1BoKIkJKagjaHA1OnTgXHcXjqqadYsagSeno1Gg0CAgIaFy1aFE70G+lIrgLB+vp6/+Dg4DJlYuSbbrqJVQPPnz8fRIQbb7wRLpcLffv2VbtcIC8vD8eOHYNOp2OiUSLCgw8+yGJk9ec831Fw6e9v7gDaVFM7cuRI7N69G1OnToVWq0VzczOeeOIJ8DyvdCvR/OxHFX18+umnKCwsBBHhtfnzsX79evTv3/8noDE0NPQntZCquFQQBEyfPh0AcNVVV3UQnKSmpsLjcePbrVvZ4psyZQqcTicThqjupqKiQgWZHlEUERMT84MSUXG/Whz/KwBBPjQ0tCkmJia3oaEhgohw5MgRstls5O/vT5mZmUREdPDgQXK73dSnTx86cOAANTQ00alTp2nUqJEUGxtL586dYwmT0LBQys/Pp7w8H2/f1tZGAQEBlJiYSGlpaZSdnU3p6emk1WqpoKCA8vLy6MSJE5SXl0fbtm+nb5XUb0REBHMrqlbvb1GzHfR8vK++8fHHHyfZ6yWDwUCZmZnUrVs35j7i4+OpqqqKjhw9Skdyc+nUqVNUUFDAUruHDh6kqqoqCgqydgCAqampJAgiHTt6lLmEQYMGUWlpKeXl5VFQUBADz0VFRXTu3DkSfcwjWSyWXQp1/C/XA/6qC0DFEm632xscHLynpKR0jCgSLly4QIWFhdSjRw9KSEig+Ph4unjxIp07d46GDBlCb7/9NhGBTp48QdddN4FSUlLo3LlzLJZe/uly2rhhI+WMGEG9evemtLRuFBfnayWjIniXy0Ver5cSEhJo9OjRrGJIrb558cUX6cCBAx0Gvz3O+HulWTznKxK94447aNq06eTvb2Yta1Rf7nK5KDQ0lDIzM4m75x6y2+1UUlJCl4qL6dTJE3T4cC7dcOMNdKHwgpKu9k22uiGOHj3KClr69etH+/fvJ5fLRVlZWRQaFsYKXB0OB2k0GkGSJIqPj9954sQJmjRpElavXv3bODJm7ty5XiKi+Pj47zUaCYIgCG63mw4cOEAcx5HVaqUBAwYQANqzZw/16tWLqYWOHDnSYVDUeSkuLqbmlhZKTkmhjIx0SknpTFFRUWQwGBhR5HQ6ye12M2WPKIpkNpspOjqaevfuTVFRUdTS0sKKVdrv9L93GY1+pLSWodTUVEpP706hoSHsO7vdbkUy5nu+qlg2Go2UmJhIKcnJlJKSSnFxcUpY2dAhjO3Rowe53W46c+YMK2JJ6JRA23dsJyKigQMHkkbJmu7cuZOUmn9Op9NVzps37wgR0apVq7xEv63DnAiALjQ0tFDR3svXXHMNmpqaYLfbsWjRIhARxo4dC1mWMXDgIKXFTAJqa2uxadMmcByn+FQOs2bNwooVK8ArGnpfD780TJkyBf/3f/+Hbdu24cKFC6iqqsKRI0ewfv16vPLKK5gyZQoyMjIYSDQYDCgsLGR8/89p+dsnnwRBwJEjR1gRhkoQZWVlYerUqViwYAG2bNmCEydOoLKyCgUF+di4cSNeeOEFjBs3DklJSYyqDg8Px9Zvt2L0n/6kkFQ8wsPDUFNbi9zcXIYfpk+fjtbWViQmJoLnOezatQt2ux1FRUWIjY0Fx3FuURTRqVOntUqa/Dd5HI0gCAKlpKR8LEmil+M4d1hYGM6dO4eGhgb1ZA4EBgaiurqaMXeSJGLnzu9QXV2NyMhICIIPFE2dOhUAkJ2dzTJul4OtpKQkdO/e/SfFHyaTCTNnzsRrr70GjuOwadMmnD17FpLSqOHnFoBWqwXHcYiNjUVzczNeeOEFcByHlStX4oYbbugQdRARgoKC0LNnT8TExPwEHKqA9s9KciozM5P9XU5ODgDgvffeYz/buHEji/+7deuGqqoqNDfbsXbtWhXYerRaLfr37z/t1z7qnv8Vw0GSZZkiIiI2i6KG02g0fGVlJR04cIBEUaS4uDjKys6m+vp62r9/P+Xk5JAoiuR2eyg3N5eCg4OpW7du5OuzSHT+/HkmKlHr+tVOXn5+fuTxeKigoIBOnDhBNpuNzGYzjR07lhYtWkQXL16kZ599lg4ePEhERFu3bqWUlBQa0L8/eTwe+pkaVJa3v+aaa8jPz4+2b99GHMfRyZMn6bPPPqO8vLM0f/58GjJkCEmSRLW1tXTkyBEqLi4mIl/FsVp8ohazxMbEUn1DA1VUVLBnZmdnM0CsagKysrJoy5YtxHEcjRgxQsEZPG3fvl2VgAk6nc5x1VVX7SAiqC6XfouHRq1YsSLUarWqXbq8kydPht1uR3NzM16d/+pfte+tLUhPTwfHcRg3bhwAMKug5vedTifmzZvXIdvGcRxmzJiBpUuXYsyYMRg2bBjmz5+PI0eOoLGxEQBwOPew2twJ5GukhPr6emzYsOFnc/Qqe+fv74/CwkIcOnSog8UZOXIkysvL4fV6UVNTgx9++AFPPfUUhg4diltuuQWrV69WufoO2cqtW7fi7Jmz0Gq1EEUBgiBg9+7daGtrQ1paGogIkydPhsvlYlnTTZs2obm5GcXFxUhMTATHcR5RFBEVFbXn1wz//l0Xr+z2tYIgeDmO80RGRqLw/Hk0NTbhwIED0Gq1CAoKQl1dHebOnQue5xEZGYnS0lIcPHSQkSVarRZnz57F1q1b2cCqJFFmZiYcDgfsdjuamppYZ6/W1lZ89dVXjBsYMGAAli1b1oFXmD59OsMG7Ys7VfJKpWdNJhOWL1+OuLg4ZppPnTqFhoYG1NXVweFwoKGhAS6XC0VFRbBarex7q7n9mpoaRnJxHCE52beo9+7dyyjvDRs24PDhw6xDeGVlJZqbm/Hll1+yOkCNRoPevXvPViKZ3/QR9yIRcf369btFKej0qLl3m82GxsZGjBw5EkSEVatW4eTJk2yXrf3yS7Q52jr4y2XLlqGxsRHh4eEsW6juLlVzUFpaiqKiIjgcDqxcuRJ+fn4gIkyYMAGXLl0CANx2220QBAF79uyBy+XCkCFDGLhTs3P33nsvAODtt98GEeH1118HAJw4cQK9evVilTyHDx9mAK2kpAStra14+eWXf6IJGDp0KADg3nvvZe8zbdo0AMALL7wAIkJYWChsNhtTRc2ePZu1hrvrrrtU9s9rMpkcs2bNSv3Nn0eouoG1a9eGWK3WBvWkiwkTJjA3oAo4xo0bB7vdjtdffx0bNmxAZWUlXC4XHnvsMTZgt9xyCwCoTRuh1+sZcp4xYwacTicuXbrko5NXrmTJounTp8Nut7MGi6owJDo6GmfPnkVDQwNbiO0B58aNGxlVfN9997F+whUVFfiTguTj4uJw6NAh2O12lJSUoLGxkTF9Op2WKZlef/11eDweJkPjOA7r1q0DAJSUFGPFihVYunQp6urqkNApHoIgYN++fWhubsb58+eV1DXnEUUBkZGRu9QO5vQ7uARRFKlTp04rlL4B7oCAAJw8eRKNjY3Iy8tDcHAwDAYDjh49CgC4dOkS1qxZg/LycvUUTxARYmJiYLfbsW7dug4ZQY7jEB/vy5a53W4sWbKEWYZhw4ahpaUFZWVlcLvc6k5C165dERkZiZiYGBQUFECWZdx115145plnAABff/019Ho9MjJ6ICIiXMnYvQy3242qqipcunQJCQkJys4Nw65du+DxeLB7927mttpnAgsLC3Hw4AG0O1ASDQ0NKCoqwjfffIOqqkoAYC5i+PDhqK+vR0tLCz766CP1fT1arQZZWVn3/xbkX/9UcmjUqFFjfPXxWpmI8NJLL7HkxrRp05iAcuTIkQgKCgIR4YsvvoDL5UKfPn3YTly3bh0cDgc6derEjoZVj409ceIEPv/8C5bYCQiwYP/+/axL6fPPP8+aQRw4cACnT59GdHQ0oqOj8e2337LU7+LFi2EwGNC7d280NDRg+fLljJNYtWoVM8srV65ktf1WqxVHjhxhGKN9Imv8+PEAgEceeYRZmXtnzAAAlg6PiYnBuHFjmUj2448/RktLC+rr61VA6ZUkCQEBAQ3vvPNO2O/pOFqVFNIHBQWdVyZLzsjIQHV1NZqaGvHdzp0d4moVEI0dOxYAsGDBAvZ3aoTQ3s/6dpkRDz30EPR6HWv68PzzzysWpYgpgbRaLVatWoW2tjZUV1cz9Q4R4emnn8btt9/O/jx27FjmqtSKYUEQ8Pjjj6Ourh5erxc333wzM+nR0dGYNm0a2/2qKPT7Xbtgs9kQHx/H9IqHDx9GW1sbUlNTWSNM9blxcXG4ePEibDYbdu/erWoH3KIoonPnzp8p5I9Av6NL4DiOunXr9qLSj9fNcTzWrVsHm82G+vr6DkIIdaD9/Aw4ffo0ioqKEBISwoDfsWPHUFdX55Nj80KHziCq6R/QfwAAYPv27R3Ste+++y7a2trQ0NCA9Yq4RBRFVqpuMBiQnZ0NjuNgMBhw6NAh1NTUwOFwYNr0aew+gwYNwpkzZ1BVVYXIyAgW1l0uCx85cqRP7fz+QvZvhwwZAgAdnt/+3Z944gm0traiubkZM2bcp+IJ2c/PzzthwoQhv4b48z96qaZq1qxZyUajsU2j0Xjbg8GmpiZ88cUX6NatG+655x6sXr2aoe8nnngCAHD//fezAbr11lsBAO+88w6zAmqfHlEUYbFYcPr0abz++usKRvD9u0cffRROp5NFCeo9RVHE/v37sXPnThw7doyZcSLCq6++ira2NpSWlqKhoQFXX3012jd7/uqrr7Bly5YOMb96ZqFWq8XBgwdht9uRkpzMUr2rV69m4aVGo8H69euxcOFCTJw4Eenp6Th69ChsNhvOnctDSEgIBEHwCAKPyMjIXEX7x9Hv8OKV7NVGtYO2wWDA/v370djYiLKyMtTU1DA/XFBQgODgIISGhqKiogJHjhxRZFa+HbZnz1643W71kCfWlEmSJDzzzDO4+567O+yqe+65B3a7HWVlZaisrER5eQWzDMHBwThx8iRaWlrgcrnw7bffsl05ePBgFl7W1NSgrKyMoXz18+yzz+Kuu+5iFupyDcOrr77K3ET37t3hcDhw8OBBcByHq666ip0eAgBVVVWoqKiAw+HA88+/wMCfRqNRqd/fB/j7W2Bw9OjR1/jAoE5WwyuHw4GysjKUlJTggw8+wA033ID4+HgYjb4Yfv78+QDA/DjHcRgwYAAcDgdyc3Ph7+/P6gYiIiIYq6bo5bBjxw6m3SstLYXdbsemTZsYgOvSpQsqKytRVlaG6upqFpmo3EBubi4aGxtRWlaGiooK1q0kNjYW6qlfvXr1gsViYfgjPT0dNpsNeXl5CAwMZBjnww8/AABMmTIFPM/DYrGga9eumD59OtasWYPKykpUVlaioqICnTt3BsfxsiAI3qCgoNLCwkL/3/px8f/I6d9ieHj4cUEQvKIoyFarFadOnUJ9fT0uXLiAkJCQDlIt5RAK1NbW4uDBg0qnLW0HkKcmUlQX8Nf/F5Camor58+ejuLgYdrsdly5dQltbG5OEUbuCi/LycjYBarxORHjjjTeY7LulpQWnT5/GI488grCwsA6ydTX88/f3x4EDBzpI2JXj6NHS0oLjx493aD+jfkaMGIGGhgZ2ZpG6+yVJRFpa2jyF+RPod3wJRET9+vW7WwFKHlKqbdTQat68ecyUqtm99rTslClT2ATr9Xps3boVADqof1VuX92NRITu3btj+/btLB2tau1UU+1wOlFWVsZay6tkkarlU1W/y5Yt67BI29f3aTQSeJ7HypUrAQDPPfdcB+nXRx99BAC44447QETo378/oqOjGZ+xZctmNDc3o6qqEhkZGeA4zitJgtdi8W968803Y+jvHxH727/UwxFqa2vNISEhlwRB8AqCIIeFhaGgoAANDQ0oKChAWFgYOI7D5s2bcfLkSYiiiISEBFRXV+PEiRPw9/dnIVZMTAzy8vLg8Xhwzz33dBCMqty+waBnO3TRokUAgA8++KAD86cCvYqKCjQ1NWHQoEEsZNv5/fcAgDlz5rCJb485fMkdn+V57733AACrV69mp5lwHIc+ffqgra0Nubm50Ol0iI2NhcPhYItkxIgRTDO5dOlStvtFUUSXLl0W/zcbQP5brECvXr1mtbcCTz/9NKseevLJJxkx5PV6ocid8eyzz3aoIFZ5/oyMDBQXF0OWZcyYMYNNXHuxR3v38O6776KoqIgVew4aPAiNjY0oLy9HdXU1ioqK0KlTJ586NyUFNpuNkTjqbv1r0aqe4Y33338fALB161aYzWalK5mOJXm8Xi+uvfZaEBHef/99NDY2Ijo6GjzPY+3atWhu9lHNvXr1gnIKiNdsNjsee+yx1N/97r/cCtTU1JiCgoIuieJfrUB+fj7q6+tReL4Q6vnCmzdvxunTp6HVahEcHIxz586hoqICSUlJ4DiOLYLevXvj/PnzjCRS+YDLd6r6848++gg33ngjKywpLS1FZWUl6urqcPz4cbY4Zs+ezSqRL7csqu8PDw9nvP6mTZtgtVoZj0BK2RoAbNiwoUPpupraHjlqJDtD6fLdn5iYuOR/afeziIDjOMrOzu5gBR599FG0traitbWVUaRXXXUVADDzPnnyZADAypUrf1J/l5KSgoMHD7JEjnosjCojV2N0URRhNJmQmZkJjuNgsVhw7NgxdhLXN998w/x7VlYWlCNwfqLzJyKMGjUKZ8+eBQAsW7ZMOYCKYwyl1WpFfn4+GhsbWWZz+fLlKC8vh9VqhSiK2LRpE1paWlBVVYW0tDTF90uy2WxWs37/G7v/cisAwBQeHl7kiwhEOTAwEKdOnWZJErWx5LJly1BRUYGgoCCIoogNGzYAAKNh2/PuVquVga3Kykr8+c8Pw2QyseIPFTyq7kBNJm3cuBGNjY1oaWnBW2+9xaxH+0XWvgl1bGws3n33XQBAW1sbc0uqBkCNVBYsWAAArCh20KBBHXQIEydOhM1mQ0tLC9599131fTyCIKBr165L/+d2/+VYYNCgQXf4xB0+rcBdd93FjkhTU8WdEjvBZrOxnEC3bt1QU1OD4uJiREVFsT4B7btrT558C3MJx44dwz333IOAgICfdOpWXch7773HkkaPPvooq/BRfXj7iZ87dy6qqqoAAHv27GFklGoh2tPAsizj4MGDCAgIgE6nw6FDh3Do0CFotVqYzWbGFF68eBFxcXFQN0NAQEDLc889l/w/t/sv4wV4AFJUVNQxhUP3aDQa7Nq1C01NTairq2MVOLNnzwYA9O3r66L95z//GbIsY82aNWzXXd4xPCIiAi+88AIrBj1//jxeeuklZGVlwWgydojBH3roIbS2tsJms2HcteMuE3xaMWrUKCxevBgNDQ0AgHPnzmH69OlsslXAqXIB4eHhOHv2bAfRywMPPAAALMKYPXs2c3kq8NXpdB5RFNG9e/eXfwstX/4j7OD48eOvNhgMTDE0fPhwNDY2orGxEdu2bYNOp4Ofnx8OHDiAQ4cOMVbteyU8e/DBB3/SV6i9uY6Li8Ps2bNx/PhxdkLnufxzWL16NeMVrr9+EtocDlRVVaFHzx5KP4BZ2LJlC8rKygAAHo8bu3btwp133smsSfuzAtQFQErv4fb5iqSkJNjtdkZapaamoKSkBE1NjTh69KjKZso8z3uDgoKqdu7cGfS/vPt/cs5AUlLSFsVHe4gIS5YsUUxyM5NR9evXD263G88//7wvSeNoQ01NDerr6zF06NCfLIL25lglZAYOHIjnn38e27dvh81mw5kzZyBJEjIzM9HY2MjYSFU4Wl5ehm+++QaPPvooevTo0aGYtH2E0T4kfPTRR+D1etlRrw88cD/WrVuHixcvIjg4GDwvYNWqVSzVPGnSxHaCDy0GDRr0AMdxv6+M3y+1Ao888kiGxeLvkiTJIwiCNyEhAcXFxaitrUVxcTEDhKpix+v1Yu7cuRg3bhxcLhcKCwsRFRX1s02YVBCncv/UrpizZ8+eSogZgvLychw+fBiCICAoKAg9evRg/XqoXU+j9uGgJPkKSNTJz8nJgdfrRUlJMYYNG4bly5ezDl9q96/JkyejpaUFNlsT1q5dC47jodVqZYXYOg5Aq7hHjv4I16RJkwRBECg9PX2+MsAe1S+3tbWhqck3UIIgMHWu2kRCBY5tbW3YunUr/Pz82KT/3Okd7Y9zaa890Gq1OHXqFJObqUme9sfS/Nw927d5SUpKQlFRESorKzFw4EB2/9mzH2cV0bGxsSgsLERdXR0qKyuRltZNDTk9RqPRe8sttwz+3eX7f6WwkFco4os8z3u1Wq2s1WqxY8cOpo1TXYG6k9VQbsqUKSyVrJacqbu0PXFz+WJQAaPqt7///nvWfUud8Mv/3U8riHxdvgICAnDo0CEGENWYX11oqutYsWIFmpubOwA/vd4X9qWmpn78e1T7/NrawfHKDvUQETJ7ZaK2thZVVVWoqqpCRkYGC/WsVis+/vhjAMDevXuZrk/l7C/vNdh+8i9v1MhxHJYtW4ann57DiJy/PfHiT6zM119/zUSdhYWF8Hq9ePzxx8HzHCTJtwhuv/12pvPbu3cvDAYDNBqNzPO8bLUGVaxYsSKUiPg/AvD7m9yAAghXtQeEc+bMQVtbG+rr69npY1lZWThxwofqly5dCovFgvDwcJw4cQIAcPfdd/1sx9GfWwzqLt2xYwfjHv5W0ejPHVClJpg+//xzpi/Ys2cPAGDt2jUIDg5mRR5VVVWor69HdnY2q/PT6XQYOnTo5D+c6aefl45xH3/8cXRQUFDd5a6gqakJDQ0N2LhxI8rKyuD1enHvvdM7NJxMS0tjJ29NnHidgv71f8eEa5lMvL6+Hvn5+QgKCmLavvbVwj8XXbzyyisAgO937YLRaGKm3mAwYMGCNwAABw8exI8//oj6+no4HA48/fTTqs7Pw/M8kpKSvlLKvP64k3+5K8jJyblVcQXu9lWy5eXlaG5uRl5eHiOJ1IlRKd8BAwagrq4ONpuNafj+1iJQ0fvzzz+PlpYWNDU14b777vu7x8Cpk//0008r1ULHERkZxUgj33FwAtMvKodAo6mpCdu3b1dxh8zzvBwYGFj37rvvRv9RYv5/2BVIkkTJycmfK4kcz1/Rvq/R87lz55CYmAhBECBJEpYuXYovv/ySWYKrr74adru9Q9XPXw+b+ukCuPvuu1kTxjFjxvzsAmg/+SozWVh4HsnJnVmBSF5eHp588kmGU8aMGYOamhpUVVWylrNKU2u3Xq9HTk7OrX940/83XAG/du3akODg4GKe5706nU9DuGTJEjQ3N6OxsRGHDh2C2WwGz/NMgKnWC6iJltbWVjQ0NLBSLhUTtE8RExHi4+OZ4MRkMv2MC/irz1cn/9KlS0yxpNfrsX37drS2tjEZWHp6OmprfeFea2srS17p9XoPz/NITU1drpR4XZn8v+UKJk2adLUS27slSfJaLBYcPnwY9fX1sNvtWL58OQsLVZOsJnNIaS+nmvbx48f/RCOggkBBEHDg4AGsXr2K1fWpiN9nsn1Ace7cuQCA4uJiVsUjCAKWLVsGAJg4cSJTGh8+nMsqh994Y4H6bJnneYSFhRWeOHEiQOnJwF2Z8Z+/RFEUqWfPnq8rZ/65iQg9emSgstKHB9xuNwv7eJ7H4sWLf1KGNX78eDQ1NaG1tbWDpvDybp1Lly3t0Ia+fahHSo0AAFy4cIHV7+t0OhYFqEJTjUaDdevWsb6I27dvVzWDXlEUPSaTyTNlypRBV0z/P5YxFACI0dHROxX+3aOqbFQdn91uw+TJk5mfX7p0qVJ2/TzzxVdffTVqa2vhcrlYQYhKAql+fdasWUx+1j69LIoiPvjAJ+fOy8tjsnOLxYJVq1YBAJ566im24BYsWMBKz86fP6/29WG1/X379n2c53kaNGiQeGWK/8GqopdffjnGag2q5nneq9frZZUfUGsK7HY7872SJDFx5nvvvcd895AhQ1BaWgoArNZPkiQm3RoxYgRj8NSfmc1mrF27lukKEhMTGeDbtm1bB42iqmpyOByoqKhAXV1du1JxnVsJ+Va1C/mumP5/Bg/ceOONV5tMJq8gCB6dTuclInz44YdwOp2oqqpCWVkZevfuzfyy2tRh1apVMBp9+f8+ffqgoKCgw+LgeR6SJCE4OBiBgYGMGIqKisLu3T8AAH744QeEh4ezTma5uYcBgIWMapTS2tqK0tJSOBwO3HbbbQz0cRyHsLCwU0pxB38l5PsXu44NGDDgMcUvu1Uad+PGjbDb7UzR2/5UEvWMga1btyIqKoq1Zs3NzQUArFu3jpWj+6RlWqY0VrV+X3/9NROJZmVl4+zZs7Db7QzwkXKMjM1mQ1lZGZxOJyN7FNDnDQwMbHzwwQe7XvH7vxAUajQaSktLWyKKIrRarVsQBAQGBmL//v1MRVRQUMD89Ouvv87O/ImIiGD+PioqEtu3bwcA7N+/v0MTqZEjR7KGDYsXL1ZyCiJEUUT//v1RXFyMpqYmTJ06tcPBUurOb3eci1cQBI/RaMSECROuvTL5v1LWEICUkJCw05cv0LtV1c/Zs2dRV1eHxkafymbJkiUAgJ07dzIFT3t9n8ViwaeffsqKUfv164fJkyejra2tQ2UPtetFSEqVkUo3L1y4kBWctra24vPPP2cqYkmS3Eo/vz8r8q4roO/XAoVfffVVaHh4+CnlqHmPmgcoKipSyJcKuN1u7Ny5EyaTiTWEjI6Oweeff846lEuSxPj8iooKNDc3dygwIaU30aJFizo0keratSsKCwvhcDhQUlKC5uZmbNu2DUajUV0AbkmS0L1797eV85OuTP6vDQrnzp3bOTg4uIzjeBgMBpmI0LdvX6XCpwqVlZU4ciSXnfIhiiKys7PR3NyMsrIy1h2MiPDYY4/B5XLBZrOx8wxUihgAjh8/jpCQEAYQR44cidLSUlZ0+uOPP8JqtaoCErcgCEhMTPwSAH8F8f8bF8H06dOzAgMDbUoljkyK9r66ulppQdOECxcuoJty8BLH+RJLhYWFcDqdLO4npUZQVRpxHIc5c+YAADZv2YLg4GBGCKnEUlVVFWw2G3JzD7NKJjXci4mJ+QGAUal/uDL5/45LJVKuu+66Yf7+/k6e573qIhg2bJiShKlCbW0tioqKkJWV1a7kPJEpeB544IGfHDKxcOFCJvBQz/9R3UFTUxPKyspgs9lw/PgxxMbGtAv3COHh4Sc2bNjwu2rk9LuODDiOo7Fjx04yGo2yIPBeg0HvJUVeXl1djaqqKtTV1aGsrIxp9XieR1BQEDZv3tyhWaPZbMbnn38OAHjrrbcYoCMi3HnnnazlnM1mw9GjR1nnUDXWDw0NLX7ttdeiryD+/8IiGDBgwE16vV4WBEE2GAxe1RKo7kC1BqqZF0URBoMBK1euYN3IVivUrlqbqE7+ww8/jNbWVpSUlMButyM3N5d1BlcnPzg4qPSJJ55IuzL5/91FcIefnx8EQfCqi+Cqq65CWVkp6urqUFVVhYaGBpY7UBNCb7zxhlL84cHMmTNZPoCUDKDL5UJJSQlaWlpw4MABRiqpk2+1BpROnz49rX3Z25Xrv7AIeJ6n/v3732owGOT2i6BPnz4oKipCQ0MDysrK0NbWxtLGKrh75ZVXWKJI1fu/++67rLNYW1sbdu3axTqE/HXyrWzyr+z834glGDRo0E1Go1FuDwy7du2KU6dOobm5GSUlJXA4HHjllVcUVZHYrnCUg8lkYp1K1f7D7SlhdfJDQkJKZ86ceWXyf4uWYOTIkTf5+5tlpRJYJqUwY//+/WhtbcWlS5fgdrvxySefdED6kZGR+P777+FwOFBUVASXy4VPP/2UpYd1Op2H4ziEh4cXvfDCC1cm/7e8CMaPHz/ebDbblUXgIaWeYNOmTR1M+44dOxASEoK0tDScPn0adrsdxcXFcDqdWLBgATiOg5p/4HkeoaGhJ+bNmxd7xef/xhcBEdHNN988xGq11nIcz0y3Xq/HkiVL4HK5GJt39OhR1s1DxQmzZ89WwKLa4pZDdHT0/hUrVkRc2fm/I7Jo5syZ3UNDQ4s4jodOp3OriZ1nn32GCThqa2tRWVnJKo7by8ckSXILgoCEhISttbW15iuTT7+/biTz58+PjYqKOqx083arYd6dd96J+vp6VFdXo7GxERcvXmxXbq7zCoLgkSQJKSkpnwLQXGH4fseLoLa21hwXF7dWkXt79Hofazh48GBcunQJhw4dYj2EDQafmEOv1yMzM/NV9bDJK5NPv+9UMgC+W7du/9fugGrZV97dmcm+VKxgNBo9V1111XQlpctfSez8j9QfSpJE/fr1e8BoNDrbF6JyHEGr1bqVk75qr7/++j+169VzZfLpf0huzvM8jRs3bnBQUFCJUgnkVsFeRERE7pw5c1J/t+3Zr1z/eJi4YMGCuOjo6O2qyDQ1NXUFANOVGJ/+OMISAEJ6evqbvXr1evQK2PuDgkPF17OzDf6ovvGPjAvUFSBf2RZXrj/k9f8A6xLkhPyYH7kAAAAASUVORK5CYII=";
    const closeIconUrl = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
      ? chrome.runtime.getURL('icons/close_icon.png')
      : '';

    root.innerHTML = `
      <button class="aegis-fab" id="aegis-fab" title="Analyze email with Aegis AI" style="display: none;" aria-label="Scan email with Aegis">
        <img src="${iconUrl}" alt="" class="aegis-fab-logo-icon"> Scan
      </button>

      <div class="aegis-analyzer-overlay" id="aegis-analyzer-overlay" role="dialog" aria-label="Aegis Phishing Analyzer Panel">
        <div class="aegis-analyzer-header">
          <h3>
            <img src="${iconUrl}" alt="" class="aegis-header-logo-icon">
            <span>Aegis Phishing Analyzer</span>
          </h3>
          <div class="aegis-analyzer-header-controls">
            <button class="aegis-header-btn aegis-reload-btn" id="aegis-reload-analyzer" aria-label="Reload Aegis analysis" title="Re-scan current email">
              <svg viewBox="0 0 40 40" width="28" height="28" class="aegis-reload-badge-svg" aria-hidden="true">
                <circle cx="20" cy="20" r="18" fill="#000000" stroke="#ffffff" stroke-width="2.5"/>
                <path d="M26 14a8 8 0 1 0 2.5 6M26 9.5v5h-5" fill="none" stroke="#ffffff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </button>
            <button class="aegis-header-btn aegis-close-btn" id="aegis-close-analyzer" aria-label="Close Aegis panel" title="Close panel">
              <svg viewBox="0 0 40 40" width="28" height="28" class="aegis-close-badge-svg" aria-hidden="true">
                <circle cx="20" cy="20" r="18" fill="#000000" stroke="#ffffff" stroke-width="2.5"/>
                <line x1="13" y1="13" x2="27" y2="27" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round"/>
                <line x1="27" y1="13" x2="13" y2="27" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round"/>
              </svg>
            </button>
          </div>
        </div>

        <div class="aegis-analyzer-status" id="aegis-analyzer-status">
          <div class="aegis-spinner"></div>
          <p>Running Multi-Layered Analysis...</p>
        </div>

        <div class="aegis-analyzer-results" id="aegis-analyzer-results" style="display: none;">
          <div class="aegis-risk-score-card" id="aegis-risk-score-card">
            <div class="aegis-score-circle" id="aegis-score-circle">
              <span id="aegis-score-value">0</span>%
            </div>
            <div class="aegis-score-text">
              <h4 id="aegis-risk-level">Safe</h4>
              <p id="aegis-risk-desc">No significant threats detected.</p>
            </div>
          </div>

          <div class="aegis-layer-analysis">
            <h4>Multi-Layered Defense Status</h4>
            <ul class="aegis-layers-list" id="aegis-layers-list">
              <li id="aegis-layer-sanitization"><i class="fas fa-minus-circle aegis-icon-skip"></i> Pre-processing: HTML Sanitization</li>
              <li id="aegis-layer-auth"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 1: Auth (SPF/DKIM/DMARC)</li>
              <li id="aegis-layer-attach"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 2: Attachment Check</li>
              <li id="aegis-layer-behavior"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 3: Behavioral Analysis</li>
              <li id="aegis-layer-nlp"><i class="fas fa-minus-circle aegis-icon-skip"></i> Layer 4: Deep NLP Context</li>
            </ul>
          </div>

          <div class="aegis-xai-box" id="aegis-xai-box">
            <h4><i class="fas fa-brain"></i> Explainable AI (XAI) Insight</h4>
            <p id="aegis-xai-text">Analysis in progress...</p>
          </div>

          <div class="aegis-actions">
            <button class="aegis-btn aegis-btn-primary" id="aegis-whitelist-btn" style="display: none;" aria-label="Whitelist sender">
              <i class="fas fa-user-check"></i> Whitelist Sender
            </button>
            <button class="aegis-btn" id="aegis-block-btn" style="display: none;" aria-label="Block sender">
              <i class="fas fa-ban"></i> Block
            </button>
            <button class="aegis-btn" id="aegis-report-btn" style="display: none;" aria-label="Report false positive">
              <i class="fas fa-flag"></i> Report False Positive
            </button>
            <button class="aegis-btn" id="aegis-full-analysis-btn" aria-label="View full analysis report">
              <i class="fas fa-search-plus"></i> View Full Analysis
            </button>
          </div>
        </div>
      </div>

      <div class="aegis-fam" id="aegis-fam" role="dialog" aria-modal="true" aria-label="Aegis Full Analysis Report">
        <div class="aegis-fam-backdrop" id="aegis-fam-backdrop"></div>
        <div class="aegis-fam-panel">
          <div class="aegis-fam-header" id="aegis-fam-header">
            <div class="aegis-fam-header-left">
              <div class="aegis-fam-logo"><img src="${iconUrl}" alt="" class="aegis-header-logo-icon"></div>
              <div>
                <div class="aegis-fam-title">Aegis Full Analysis Report</div>
                <div class="aegis-fam-subtitle" id="aegis-fam-subtitle">Comprehensive Threat Intelligence</div>
              </div>
            </div>
            <div class="aegis-fam-header-right">
              <div class="aegis-fam-zoom-controls" id="aegis-fam-zoom-controls" role="group" aria-label="Magnification Options">
                <button class="aegis-fam-zoom-btn" id="aegis-zoom-out-btn" aria-label="Zoom out" title="Zoom Out by 5% (Min 70%)">
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round">
                    <line x1="5" y1="12" x2="19" y2="12"/>
                  </svg>
                </button>
                <button class="aegis-fam-zoom-btn aegis-fam-zoom-display" id="aegis-zoom-reset-btn" aria-label="Reset zoom" title="Reset / Toggle Zoom (75% / 100%)">
                  <span id="aegis-zoom-level">75%</span>
                </button>
                <button class="aegis-fam-zoom-btn" id="aegis-zoom-in-btn" aria-label="Zoom in" title="Zoom In by 5%">
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round">
                    <line x1="12" y1="5" x2="12" y2="19"/>
                    <line x1="5" y1="12" x2="19" y2="12"/>
                  </svg>
                </button>
              </div>
              <div class="aegis-fam-risk-badge" id="aegis-fam-risk-badge">—</div>
              <div class="aegis-fam-header-controls">
                <button class="aegis-fam-header-btn aegis-fam-reload-btn" id="aegis-fam-reload-btn" aria-label="Reload full analysis" title="Re-scan and refresh analysis">
                  <svg viewBox="0 0 40 40" width="28" height="28" class="aegis-reload-badge-svg" aria-hidden="true">
                    <circle cx="20" cy="20" r="18" fill="#000000" stroke="#ffffff" stroke-width="2.5"/>
                    <path d="M26 14a8 8 0 1 0 2.5 6M26 9.5v5h-5" fill="none" stroke="#ffffff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                </button>
                <button class="aegis-fam-header-btn aegis-fam-close-btn" id="aegis-fam-close-btn" aria-label="Close full analysis" title="Close">
                  <svg viewBox="0 0 40 40" width="28" height="28" class="aegis-close-badge-svg" aria-hidden="true">
                    <circle cx="20" cy="20" r="18" fill="#000000" stroke="#ffffff" stroke-width="2.5"/>
                    <line x1="13" y1="13" x2="27" y2="27" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round"/>
                    <line x1="27" y1="13" x2="13" y2="27" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round"/>
                  </svg>
                </button>
              </div>
            </div>
          </div>

          <div class="aegis-fam-body">
            <div class="aegis-fam-col-left">
              <div class="aegis-fam-card aegis-fam-gauge-card">
                <div class="aegis-fam-card-label"><i class="fas fa-tachometer-alt"></i> Aegis Risk Score</div>
                <div class="aegis-fam-gauge-wrap">
                  <svg class="aegis-fam-gauge-svg" viewBox="0 0 200 120" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="aegisGaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%"   style="stop-color:#22c55e"/>
                        <stop offset="50%"  style="stop-color:#f59e0b"/>
                        <stop offset="100%" style="stop-color:#ef4444"/>
                      </linearGradient>
                    </defs>
                    <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#e5e7eb" stroke-width="14" stroke-linecap="round"/>
                    <path id="aegis-fam-gauge-fill"
                          d="M 20 100 A 80 80 0 0 1 180 100"
                          fill="none"
                          stroke="url(#aegisGaugeGradient)"
                          stroke-width="14"
                          stroke-linecap="round"
                          stroke-dasharray="251.2"
                          stroke-dashoffset="251.2"
                          style="transition: stroke-dashoffset 1.2s cubic-bezier(0.34,1.56,0.64,1);"/>
                    <line id="aegis-fam-gauge-needle"
                          x1="100" y1="100" x2="100" y2="30"
                          stroke="#1e293b" stroke-width="3" stroke-linecap="round"
                          style="transform-origin: 100px 100px; transition: transform 1.2s cubic-bezier(0.34,1.56,0.64,1);"/>
                    <circle cx="100" cy="100" r="6" fill="#1e293b"/>
                    <text x="15"  y="118" font-size="10" fill="#6b7280" text-anchor="middle">0</text>
                    <text x="100" y="18"  font-size="10" fill="#6b7280" text-anchor="middle">50</text>
                    <text x="185" y="118" font-size="10" fill="#6b7280" text-anchor="middle">100</text>
                  </svg>
                  <div class="aegis-fam-gauge-score-wrap">
                    <div class="aegis-fam-gauge-score" id="aegis-fam-gauge-score">0<span>%</span></div>
                    <div class="aegis-fam-gauge-label" id="aegis-fam-gauge-label">Analyzing...</div>
                  </div>
                </div>
              </div>

              <div class="aegis-fam-card">
                <div class="aegis-fam-card-label"><i class="fas fa-envelope-open-text"></i> Email Metadata</div>
                <div class="aegis-fam-meta-grid">
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">From</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-from">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-domain aegis-fam-meta-key">Domain</div>
                    <div class="aegis-fam-meta-val aegis-fam-meta-domain" id="aegis-fam-meta-domain">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">Subject</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-subject">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">Time</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-time">—</div>
                  </div>
                  <div class="aegis-fam-meta-item">
                    <div class="aegis-fam-meta-key">Attachment</div>
                    <div class="aegis-fam-meta-val" id="aegis-fam-meta-attach">None</div>
                  </div>
                </div>
              </div>

              <div class="aegis-fam-card aegis-fam-xai-card">
                <div class="aegis-fam-card-label"><i class="fas fa-brain"></i> XAI Explanation</div>
                <p class="aegis-fam-xai-text" id="aegis-fam-xai-text">—</p>
                <div class="aegis-fam-xai-footer">
                  <i class="fas fa-info-circle"></i> Generated by Aegis Explainable AI engine
                </div>
              </div>
            </div>

            <div class="aegis-fam-col-right">
              <div class="aegis-fam-card">
                <div class="aegis-fam-card-label"><i class="fas fa-layer-group"></i> Multi-Layer Defense Breakdown</div>
                <div class="aegis-fam-layers" id="aegis-fam-layers"></div>
              </div>

              <div class="aegis-fam-card" id="aegis-fam-indicators-card">
                <div class="aegis-fam-card-label"><i class="fas fa-exclamation-triangle"></i> Active Threat Indicators</div>
                <div class="aegis-fam-indicators" id="aegis-fam-indicators"></div>
              </div>

              <div class="aegis-fam-card aegis-fam-recommendation-card" id="aegis-fam-recommendation-card">
                <div class="aegis-fam-card-label"><i class="fas fa-shield-check"></i> Aegis Recommendation</div>
                <div class="aegis-fam-recommendation" id="aegis-fam-recommendation">—</div>
                <div class="aegis-fam-action-row">
                  <button class="aegis-fam-action-btn aegis-fam-btn-whitelist" id="aegis-fam-whitelist-btn" style="display:none;" aria-label="Whitelist sender">
                    <i class="fas fa-user-check"></i> Whitelist Sender
                  </button>
                  <button class="aegis-fam-action-btn aegis-fam-btn-block" id="aegis-fam-block-btn" style="display:none;" aria-label="Block and report sender">
                    <i class="fas fa-ban"></i> Block & Report
                  </button>
                  <button class="aegis-fam-action-btn aegis-fam-btn-report" id="aegis-fam-report-btn" style="display:none;" aria-label="Report false positive">
                    <i class="fas fa-flag"></i> False Positive
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(root);
    console.log(`${LOG_PREFIX} Overlay DOM injected.`);
  }

  // ============================================================
  // DOM Element References — resolved after injection
  // ============================================================

  /**
   * Lazily resolved element references after injectOverlayDOM() has run.
   * Using a getter pattern avoids null references at script parse time.
   */
  const el = {
    get fab()              { return document.getElementById('aegis-fab'); },
    get overlay()          { return document.getElementById('aegis-analyzer-overlay'); },
    get closeBtn()         { return document.getElementById('aegis-close-analyzer'); },
    get reloadBtn()        { return document.getElementById('aegis-reload-analyzer'); },
    get status()           { return document.getElementById('aegis-analyzer-status'); },
    get results()          { return document.getElementById('aegis-analyzer-results'); },
    get scoreCircle()      { return document.getElementById('aegis-score-circle'); },
    get scoreValue()       { return document.getElementById('aegis-score-value'); },
    get riskLevel()        { return document.getElementById('aegis-risk-level'); },
    get riskDesc()         { return document.getElementById('aegis-risk-desc'); },
    get layerSanitization(){ return document.getElementById('aegis-layer-sanitization'); },
    get layerAuth()        { return document.getElementById('aegis-layer-auth'); },
    get layerAttach()      { return document.getElementById('aegis-layer-attach'); },
    get layerBehavior()    { return document.getElementById('aegis-layer-behavior'); },
    get layerNlp()         { return document.getElementById('aegis-layer-nlp'); },
    get xaiText()          { return document.getElementById('aegis-xai-text'); },
    get whitelistBtn()     { return document.getElementById('aegis-whitelist-btn'); },
    get blockBtn()         { return document.getElementById('aegis-block-btn'); },
    get reportBtn()        { return document.getElementById('aegis-report-btn'); },
    get fullAnalysisBtn()  { return document.getElementById('aegis-full-analysis-btn'); },
    // Full Analysis Modal
    get fam()              { return document.getElementById('aegis-fam'); },
    get famReload()        { return document.getElementById('aegis-fam-reload-btn'); },
    get famClose()         { return document.getElementById('aegis-fam-close-btn'); },
    get famBackdrop()      { return document.getElementById('aegis-fam-backdrop'); },
    get famRiskBadge()     { return document.getElementById('aegis-fam-risk-badge'); },
    get famSubtitle()      { return document.getElementById('aegis-fam-subtitle'); },
    get famGaugeScore()    { return document.getElementById('aegis-fam-gauge-score'); },
    get famGaugeLabel()    { return document.getElementById('aegis-fam-gauge-label'); },
    get famGaugeFill()     { return document.getElementById('aegis-fam-gauge-fill'); },
    get famGaugeNeedle()   { return document.getElementById('aegis-fam-gauge-needle'); },
    get famMetaFrom()      { return document.getElementById('aegis-fam-meta-from'); },
    get famMetaDomain()    { return document.getElementById('aegis-fam-meta-domain'); },
    get famMetaSubject()   { return document.getElementById('aegis-fam-meta-subject'); },
    get famMetaTime()      { return document.getElementById('aegis-fam-meta-time'); },
    get famMetaAttach()    { return document.getElementById('aegis-fam-meta-attach'); },
    get famXaiText()       { return document.getElementById('aegis-fam-xai-text'); },
    get famLayers()        { return document.getElementById('aegis-fam-layers'); },
    get famIndicators()    { return document.getElementById('aegis-fam-indicators'); },
    get famRecommendation(){ return document.getElementById('aegis-fam-recommendation'); },
    get famWhitelistBtn()  { return document.getElementById('aegis-fam-whitelist-btn'); },
    get famBlockBtn()      { return document.getElementById('aegis-fam-block-btn'); },
    get famReportBtn()     { return document.getElementById('aegis-fam-report-btn'); },
    // Full Analysis Magnification Zoom Controls
    get famZoomOut()       { return document.getElementById('aegis-zoom-out-btn'); },
    get famZoomIn()        { return document.getElementById('aegis-zoom-in-btn'); },
    get famZoomReset()     { return document.getElementById('aegis-zoom-reset-btn'); },
    get famZoomLevel()     { return document.getElementById('aegis-zoom-level'); },
    get famBody()          { return document.querySelector('.aegis-overlay-root .aegis-fam-body'); },
  };

  function generateStubAnalysis(emailContext) {
    const subjectLower = (emailContext.subject || '').toLowerCase();
    const hasSuspiciousKeywords =
      /urgent|password|account|verify|suspended|invoice|wire|transfer|click here/.test(subjectLower);
    const hasAttachments = emailContext.attachmentCount > 0;
    const hasExternalLinks = (emailContext.links || []).some(l => l.isExternal);

    let riskLevel, riskClass, score, desc;
    if (hasSuspiciousKeywords && (hasAttachments || hasExternalLinks)) {
      riskLevel = 'Critical'; riskClass = 'threat-critical'; score = 89;
      desc = 'High-confidence phishing indicators detected.';
    } else if (hasSuspiciousKeywords || hasExternalLinks) {
      riskLevel = 'Warning'; riskClass = 'threat-warning'; score = 58;
      desc = 'Suspicious patterns detected. Review carefully.';
    } else {
      riskLevel = 'Safe'; riskClass = 'threat-safe'; score = 7;
      desc = 'No significant threats detected.';
    }

    const attachDetail = hasAttachments
      ? `VirusTotal: ${emailContext.attachmentCount} file(s) queued`
      : 'No Attachments';
    const attachIcon  = hasAttachments ? 'fa-exclamation-triangle' : 'fa-minus-circle';

    return {
      riskLevel,
      riskClass,
      score,
      desc,
      layers: {
        sanitization: { text: 'Pre-filter: Sanitization', detail: 'HTML Stripped — Plain Text Only', icon: 'fa-check-circle' },
        auth:         { text: 'Layer 1: Auth (SPF/DKIM/DMARC)', detail: 'Pending — Auth headers not available client-side', icon: 'fa-minus-circle' },
        attach:       { text: 'Layer 2: Attachment Intelligence', detail: attachDetail, icon: attachIcon },
        behavior:     { text: 'Layer 3: Behavioral Analysis', detail: 'Baseline: Pending sender history', icon: 'fa-minus-circle' },
        nlp:          { text: 'Layer 4: Deep NLP Context', detail: hasSuspiciousKeywords ? 'Urgency/Financial keywords detected' : 'Context appears normal', icon: hasSuspiciousKeywords ? 'fa-exclamation-triangle' : 'fa-check-circle' },
      },
      xai: riskLevel === 'Safe'
        ? 'This email follows standard communication patterns. No urgency, financial requests, or malicious payloads were detected by the preliminary analysis pipeline. Full ML analysis pending backend connection.'
        : `Preliminary analysis flagged suspicious characteristics: ${hasSuspiciousKeywords ? 'urgency/financial keywords in subject. ' : ''}${hasExternalLinks ? 'External hyperlinks present. ' : ''}${hasAttachments ? 'Attachments detected and queued for VirusTotal scan. ' : ''}Full ML scoring pending backend connection (Milestone 2.x).`,
    };
  }

  function closeAnalyzer() {
    el.overlay.classList.remove('active');
    if (currentEmailContext) {
      el.fab.style.display = 'flex';
    }
    setTimeout(() => {
      el.overlay.className = 'aegis-analyzer-overlay';
    }, 400);
  }

  function populateAnalysis(analysis) {
    el.overlay.className = `aegis-analyzer-overlay active ${analysis.riskClass}`;

    el.scoreValue.textContent = analysis.score;
    el.riskLevel.textContent  = analysis.riskLevel;
    el.riskDesc.textContent   = analysis.desc;

    const layerEls = {
      sanitization: el.layerSanitization,
      auth:         el.layerAuth,
      attach:       el.layerAttach,
      behavior:     el.layerBehavior,
      nlp:          el.layerNlp,
    };

    const iconClassMap = {
      'fa-check-circle':        { cls: 'fas fa-check-circle aegis-icon-pass' },
      'fa-times-circle':        { cls: 'fas fa-times-circle aegis-icon-fail' },
      'fa-exclamation-triangle':{ cls: 'fas fa-exclamation-triangle aegis-icon-warn' },
      'fa-minus-circle':        { cls: 'fas fa-minus-circle aegis-icon-skip' },
    };

    Object.entries(layerEls).forEach(([key, listItem]) => {
      const data = analysis.layers[key];
      const icon = iconClassMap[data.icon] || iconClassMap['fa-minus-circle'];
      listItem.innerHTML = `<i class="${icon.cls}"></i> ${data.text}: ${data.detail}`;
    });

    el.xaiText.textContent = analysis.xai;

    if (analysis.riskLevel === 'Safe') {
      el.whitelistBtn.style.display = 'flex';
      el.blockBtn.style.display     = 'none';
      el.reportBtn.style.display    = 'none';
    } else {
      el.whitelistBtn.style.display = 'none';
      el.blockBtn.style.display     = 'flex';
      el.reportBtn.style.display    = 'flex';
    }
  }

  function openFullAnalysisModal(emailContext, analysis) {
    const badge = el.famRiskBadge;
    badge.textContent = analysis.riskLevel;
    badge.className = 'aegis-fam-risk-badge';
    if      (analysis.riskLevel === 'Safe')    badge.classList.add('badge-safe');
    else if (analysis.riskLevel === 'Warning') badge.classList.add('badge-warning');
    else                                        badge.classList.add('badge-critical');

    el.famSubtitle.textContent =
      `Analyzed: ${emailContext.subject || '(No Subject)'} — ${emailContext.timestamp || 'Just now'}`;

    el.famGaugeScore.innerHTML = `${analysis.score}<span>%</span>`;
    el.famGaugeLabel.textContent = analysis.riskLevel;
    el.famGaugeLabel.className = 'aegis-fam-gauge-label';
    if      (analysis.riskLevel === 'Safe')    el.famGaugeLabel.classList.add('lbl-safe');
    else if (analysis.riskLevel === 'Warning') el.famGaugeLabel.classList.add('lbl-warning');
    else                                        el.famGaugeLabel.classList.add('lbl-critical');

    const arcLen    = 251.2;
    const offset    = arcLen - (analysis.score / 100) * arcLen;
    const needleDeg = -90 + (analysis.score / 100) * 180;

    el.famGaugeFill.style.transition   = 'none';
    el.famGaugeNeedle.style.transition = 'none';
    el.famGaugeFill.style.strokeDashoffset = arcLen;
    el.famGaugeNeedle.style.transform  = 'rotate(-90deg)';

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        el.famGaugeFill.style.transition   = 'stroke-dashoffset 1.2s cubic-bezier(0.34,1.56,0.64,1)';
        el.famGaugeNeedle.style.transition = 'transform 1.2s cubic-bezier(0.34,1.56,0.64,1)';
        el.famGaugeFill.style.strokeDashoffset = offset;
        el.famGaugeNeedle.style.transform  = `rotate(${needleDeg}deg)`;
      });
    });

    el.famMetaFrom.textContent    = `${emailContext.senderName || '—'} <${emailContext.senderEmail || '—'}>`;
    const domain = emailContext.senderEmail
      ? emailContext.senderEmail.split('@')[1] || emailContext.senderEmail
      : '—';
    el.famMetaDomain.textContent  = domain;
    el.famMetaSubject.textContent = emailContext.subject || '—';
    el.famMetaTime.textContent    = emailContext.timestamp || '—';
    el.famMetaAttach.textContent  = emailContext.attachmentCount > 0
      ? emailContext.attachments.join(', ')
      : 'None';

    el.famXaiText.textContent = analysis.xai;

    el.famLayers.innerHTML = '';
    const layerMap = [
      { key: 'sanitization', label: 'Pre-processing: HTML Sanitization' },
      { key: 'auth',         label: 'Layer 1: Email Auth (SPF/DKIM/DMARC)' },
      { key: 'attach',       label: 'Layer 2: Attachment Intelligence' },
      { key: 'behavior',     label: 'Layer 3: Behavioral Analysis' },
      { key: 'nlp',          label: 'Layer 4: Deep NLP Context' },
    ];

    layerMap.forEach(({ key, label }, idx) => {
      const data = analysis.layers[key];
      let iconClass, iconType, statusClass, statusText;

      switch (data.icon) {
        case 'fa-check-circle':
          iconClass = 'fas fa-check'; iconType = 'icon-pass'; statusClass = 'status-pass'; statusText = 'Pass'; break;
        case 'fa-times-circle':
          iconClass = 'fas fa-times'; iconType = 'icon-fail'; statusClass = 'status-fail'; statusText = 'Fail'; break;
        case 'fa-exclamation-triangle':
          iconClass = 'fas fa-exclamation'; iconType = 'icon-warn'; statusClass = 'status-warn'; statusText = 'Warn'; break;
        default:
          iconClass = 'fas fa-minus'; iconType = 'icon-skip'; statusClass = 'status-skip'; statusText = 'Skip';
      }

      const item = document.createElement('div');
      item.className = 'aegis-fam-layer-item';
      item.style.animationDelay = `${idx * 80}ms`;
      item.innerHTML = `
        <div class="aegis-fam-layer-icon ${iconType}"><i class="${iconClass}"></i></div>
        <div class="aegis-fam-layer-body">
          <div class="aegis-fam-layer-name">${label}</div>
          <div class="aegis-fam-layer-detail">${data.detail}</div>
        </div>
        <div class="aegis-fam-layer-status ${statusClass}">${statusText}</div>
      `;
      el.famLayers.appendChild(item);
    });

    el.famIndicators.innerHTML = '';
    const threats = [];
    Object.values(analysis.layers).forEach(layer => {
      if (layer.icon === 'fa-times-circle') {
        threats.push({ text: layer.detail, pillClass: 'pill-red',    icon: 'fas fa-times-circle' });
      } else if (layer.icon === 'fa-exclamation-triangle') {
        threats.push({ text: layer.detail, pillClass: 'pill-yellow', icon: 'fas fa-exclamation-triangle' });
      }
    });

    if (threats.length === 0) {
      el.famIndicators.innerHTML = `
        <div class="aegis-fam-no-threats">
          <i class="fas fa-check-circle"></i> No active threat indicators detected.
        </div>`;
    } else {
      threats.forEach((t, idx) => {
        const pill = document.createElement('div');
        pill.className = `aegis-fam-indicator-pill ${t.pillClass}`;
        pill.style.animationDelay = `${idx * 60}ms`;
        pill.innerHTML = `<i class="${t.icon}"></i> ${t.text}`;
        el.famIndicators.appendChild(pill);
      });
    }

    const recEl = el.famRecommendation;
    recEl.className = 'aegis-fam-recommendation';
    if (analysis.riskLevel === 'Safe') {
      recEl.textContent = 'This email has passed all Aegis security layers and is considered safe. No action is required. You may optionally whitelist the sender to speed up future checks.';
      recEl.classList.add('rec-safe');
    } else if (analysis.riskLevel === 'Warning') {
      recEl.textContent = 'This email contains suspicious patterns consistent with a Business Email Compromise (BEC) or phishing attempt. Exercise caution — do not click links, transfer funds, or share credentials until the sender is verified through a separate channel.';
      recEl.classList.add('rec-warning');
    } else {
      recEl.textContent = 'CRITICAL THREAT DETECTED. Aegis strongly recommends blocking this sender immediately and reporting this email to your IT security team. Do not open attachments, click links, or reply under any circumstances.';
      recEl.classList.add('rec-critical');
    }

    el.famWhitelistBtn.style.display = analysis.riskLevel === 'Safe'    ? 'flex' : 'none';
    el.famBlockBtn.style.display     = analysis.riskLevel !== 'Safe'    ? 'flex' : 'none';
    el.famReportBtn.style.display    = analysis.riskLevel !== 'Safe'    ? 'flex' : 'none';

    initFamZoom();
    el.fam.classList.add('open');
  }

  function closeFullAnalysisModal() {
    el.fam.classList.remove('open');
  }

  // Magnification / Zoom Control Logic (Min 70%, 5% increments, Default 75%)
  const MIN_FAM_ZOOM = 70;
  const MAX_FAM_ZOOM = 160;
  const FAM_ZOOM_STEP = 5;
  const DEFAULT_FAM_ZOOM = 75;
  let currentFamZoom = DEFAULT_FAM_ZOOM;

  function setFamZoom(pct) {
    const snapped = Math.round(pct / FAM_ZOOM_STEP) * FAM_ZOOM_STEP;
    currentFamZoom = Math.min(MAX_FAM_ZOOM, Math.max(MIN_FAM_ZOOM, snapped));

    if (el.famBody) {
      el.famBody.style.zoom = `${currentFamZoom}%`;
    }
    if (el.famZoomLevel) {
      el.famZoomLevel.textContent = `${currentFamZoom}%`;
    }
    if (el.famZoomOut) {
      el.famZoomOut.disabled = currentFamZoom <= MIN_FAM_ZOOM;
      el.famZoomOut.style.opacity = currentFamZoom <= MIN_FAM_ZOOM ? '0.35' : '1';
      el.famZoomOut.style.cursor = currentFamZoom <= MIN_FAM_ZOOM ? 'not-allowed' : 'pointer';
    }
    if (el.famZoomIn) {
      el.famZoomIn.disabled = currentFamZoom >= MAX_FAM_ZOOM;
      el.famZoomIn.style.opacity = currentFamZoom >= MAX_FAM_ZOOM ? '0.35' : '1';
      el.famZoomIn.style.cursor = currentFamZoom >= MAX_FAM_ZOOM ? 'not-allowed' : 'pointer';
    }
    try {
      localStorage.setItem('aegis_fam_zoom', String(currentFamZoom));
    } catch (e) {}
  }

  function initFamZoom() {
    let saved = DEFAULT_FAM_ZOOM;
    try {
      const stored = localStorage.getItem('aegis_fam_zoom');
      if (stored) {
        const parsed = parseInt(stored, 10);
        if (!isNaN(parsed) && parsed >= MIN_FAM_ZOOM && parsed <= MAX_FAM_ZOOM) {
          saved = parsed;
        }
      }
    } catch (e) {}
    setFamZoom(saved);
  }

  function attachEventListeners() {
    el.closeBtn.addEventListener('click', closeAnalyzer);

    if (el.reloadBtn) {
      el.reloadBtn.addEventListener('click', () => {
        if (!currentEmailContext) return;

        // Show loading state briefly before full tab reload
        el.status.style.display  = 'flex';
        el.results.style.display = 'none';
        el.reloadBtn.classList.add('spinning');

        // Reload the entire Gmail tab so the full pipeline re-runs from scratch
        setTimeout(() => {
          window.location.reload();
        }, 600);
      });
    }

    el.fab.addEventListener('click', () => {
      if (!currentEmailContext) return;

      el.overlay.classList.add('active');
      el.status.style.display  = 'flex';
      el.results.style.display = 'none';
      el.fab.style.display     = 'none';

      setTimeout(() => {
        const analysis = generateStubAnalysis(currentEmailContext);
        populateAnalysis(analysis);
        el.status.style.display  = 'none';
        el.results.style.display = 'flex';
        currentEmailContext._lastAnalysis = analysis;
      }, 1500);
    });

    el.fullAnalysisBtn.addEventListener('click', () => {
      if (!currentEmailContext || !currentEmailContext._lastAnalysis) return;
      openFullAnalysisModal(currentEmailContext, currentEmailContext._lastAnalysis);
    });

    el.famClose.addEventListener('click', closeFullAnalysisModal);
    el.famBackdrop.addEventListener('click', closeFullAnalysisModal);

    if (el.famZoomOut) {
      el.famZoomOut.addEventListener('click', (e) => {
        e.stopPropagation();
        setFamZoom(currentFamZoom - FAM_ZOOM_STEP);
      });
    }

    if (el.famZoomIn) {
      el.famZoomIn.addEventListener('click', (e) => {
        e.stopPropagation();
        setFamZoom(currentFamZoom + FAM_ZOOM_STEP);
      });
    }

    if (el.famZoomReset) {
      el.famZoomReset.addEventListener('click', (e) => {
        e.stopPropagation();
        setFamZoom(currentFamZoom === DEFAULT_FAM_ZOOM ? 100 : DEFAULT_FAM_ZOOM);
      });
    }

    if (el.famReload) {
      el.famReload.addEventListener('click', () => {
        if (!currentEmailContext) return;

        // Spin briefly, then do a full tab reload so the entire pipeline re-runs
        el.famReload.classList.add('spinning');
        setTimeout(() => {
          window.location.reload();
        }, 600);
      });
    }

    el.whitelistBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Whitelisted!';
      setTimeout(() => { this.innerHTML = orig; }, 2000);
    });

    el.blockBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-shield-alt"></i> Blocked!';
      setTimeout(() => { this.innerHTML = orig; }, 2000);
    });

    el.reportBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Reported!';
      setTimeout(() => { this.innerHTML = orig; }, 2000);
    });

    el.famWhitelistBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Whitelisted!';
      setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
    });

    el.famBlockBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-shield-alt"></i> Blocked!';
      setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
    });

    el.famReportBtn.addEventListener('click', function () {
      const orig = this.innerHTML;
      this.innerHTML = '<i class="fas fa-check"></i> Reported!';
      setTimeout(() => { this.innerHTML = orig; closeFullAnalysisModal(); }, 1800);
    });

    console.log(`${LOG_PREFIX} Event listeners attached.`);
  }

  function startEmailDetectionListener() {
    window.addEventListener('aegis:email-extracted', (event) => {
      const emailContext = event.detail;
      if (!emailContext) return;

      currentEmailContext = emailContext;
      el.fab.style.display = 'flex';

      if (el.overlay.classList.contains('active')) {
        closeAnalyzer();
      }

      console.log(`${LOG_PREFIX} Email detected. FAB shown for: "${emailContext.subject}"`);
    });

    console.log(`${LOG_PREFIX} Listening for aegis:email-extracted events.`);
  }

  function initialize() {
    injectOverlayDOM();
    attachEventListeners();
    startEmailDetectionListener();
    console.log(`${LOG_PREFIX} Overlay initialized.`);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }

  window.AegisOverlay = {
    closeAnalyzer,
    closeFullAnalysisModal,
    openFullAnalysisModal,
    getCurrentContext: () => currentEmailContext,
  };
})();
