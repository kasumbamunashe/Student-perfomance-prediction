from scipy.optimize import linprog

# Coefficients of the objective function (maximize profit)
c = [-40, -60]  # Minimize -Profit is equivalent to maximize Profit

# Coefficients of the inequality constraints (LHS)
A = [
    [1.5, 2.5],  # Baking time constraint
    [2, 1]       # Ingredient Z constraint
]

# Right-hand side of the inequality constraints
b = [50, 20]

# Bounds for x1 and x2 (non-negativity)
x_bounds = (0, None)  # x1 >= 0
y_bounds = (0, None)  # x2 >= 0

# Solve the linear programming problem
result = linprog(c, A_ub=A, b_ub=b, bounds=[x_bounds, y_bounds], method='highs')

# Output the results
if result.success:
    print(f"Optimal number of Beef Pies to produce: {result.x[0]}")
    print(f"Optimal number of Chicken Pies to produce: {result.x[1]}")
    print(f"Maximum profit: ${-result.fun}")
else:
    print("No solution found.")
