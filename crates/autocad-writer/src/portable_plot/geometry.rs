use super::{non_finite_arithmetic, non_finite_input, PortablePlotError};

const ARBITRARY_AXIS_THRESHOLD: f64 = 1.0 / 64.0;

fn finite(values: &[f64]) -> bool {
    values.iter().all(|value| value.is_finite())
}

fn source_proves_singular2(linear: [[f64; 2]; 2]) -> bool {
    linear
        .iter()
        .any(|row| row.iter().all(|value| *value == 0.0))
        || (0..2).any(|column| linear.iter().all(|row| row[column] == 0.0))
}

fn source_proves_singular3(linear: [[f64; 3]; 3]) -> bool {
    linear
        .iter()
        .any(|row| row.iter().all(|value| *value == 0.0))
        || (0..3).any(|column| linear.iter().all(|row| row[column] == 0.0))
}

fn product_is_identity2(left: [[f64; 2]; 2], right: [[f64; 2]; 2]) -> bool {
    const RESIDUAL_LIMIT: f64 = 64.0 * f64::EPSILON;
    const ROUNDING_FACTOR: f64 = 4.0 * f64::EPSILON;
    (0..2).all(|row| {
        (0..2).all(|column| {
            let products = [
                left[row][0] * right[0][column],
                left[row][1] * right[1][column],
            ];
            let product_magnitude = products[0].abs() + products[1].abs();
            let actual = left[row][0].mul_add(right[0][column], products[1]);
            let expected = if row == column { 1.0 } else { 0.0 };
            let certified_error = (actual - expected).abs() + ROUNDING_FACTOR * product_magnitude;
            products.iter().enumerate().all(|(index, value)| {
                value.is_finite()
                    && !value.is_subnormal()
                    && !(*value == 0.0 && left[row][index] != 0.0 && right[index][column] != 0.0)
            }) && product_magnitude.is_finite()
                && certified_error.is_finite()
                && certified_error <= RESIDUAL_LIMIT
        })
    })
}

fn product_is_identity3(left: [[f64; 3]; 3], right: [[f64; 3]; 3]) -> bool {
    const RESIDUAL_LIMIT: f64 = 96.0 * f64::EPSILON;
    const ROUNDING_FACTOR: f64 = 6.0 * f64::EPSILON;
    (0..3).all(|row| {
        (0..3).all(|column| {
            let products = [
                left[row][0] * right[0][column],
                left[row][1] * right[1][column],
                left[row][2] * right[2][column],
            ];
            let product_magnitude = products[0].abs() + products[1].abs() + products[2].abs();
            let actual = left[row][0].mul_add(
                right[0][column],
                left[row][1].mul_add(right[1][column], products[2]),
            );
            let expected = if row == column { 1.0 } else { 0.0 };
            let certified_error = (actual - expected).abs() + ROUNDING_FACTOR * product_magnitude;
            products.iter().enumerate().all(|(index, value)| {
                value.is_finite()
                    && !value.is_subnormal()
                    && !(*value == 0.0 && left[row][index] != 0.0 && right[index][column] != 0.0)
            }) && product_magnitude.is_finite()
                && certified_error.is_finite()
                && certified_error <= RESIDUAL_LIMIT
        })
    })
}

fn inverse_is_certified2(linear: [[f64; 2]; 2], inverse: [[f64; 2]; 2]) -> bool {
    product_is_identity2(linear, inverse) || product_is_identity2(inverse, linear)
}

fn inverse_is_certified3(linear: [[f64; 3]; 3], inverse: [[f64; 3]; 3]) -> bool {
    product_is_identity3(linear, inverse) || product_is_identity3(inverse, linear)
}

fn singular_transform(dimension: &str) -> PortablePlotError {
    PortablePlotError::new(
        "singular_transform",
        format!("{dimension} transform is singular"),
    )
}

fn gauss_jordan2(mut rows: [[f64; 4]; 2]) -> Result<[[f64; 2]; 2], PortablePlotError> {
    for column in 0..2 {
        let mut pivot_row = column;
        let mut best_magnitude = rows[column][column].abs();
        for (candidate, row) in rows.iter().enumerate().skip(column + 1) {
            let magnitude = row[column].abs();
            if magnitude > best_magnitude {
                best_magnitude = magnitude;
                pivot_row = candidate;
            }
        }
        if rows[pivot_row][column] == 0.0 {
            return Err(singular_transform("Affine2"));
        }
        rows.swap(column, pivot_row);
        let pivot = rows[column][column];
        for value in &mut rows[column] {
            *value /= pivot;
        }
        if !finite(&rows[column]) {
            return Err(non_finite_arithmetic("Affine2 inversion"));
        }
        let normalized_pivot = rows[column];
        for (row_index, row) in rows.iter_mut().enumerate() {
            if row_index == column {
                continue;
            }
            let factor = row[column];
            for index in 0..4 {
                row[index] -= factor * normalized_pivot[index];
            }
            if !finite(row) {
                return Err(non_finite_arithmetic("Affine2 inversion"));
            }
        }
    }
    Ok([[rows[0][2], rows[0][3]], [rows[1][2], rows[1][3]]])
}

fn gauss_jordan3(mut rows: [[f64; 6]; 3]) -> Result<[[f64; 3]; 3], PortablePlotError> {
    for column in 0..3 {
        let mut pivot_row = column;
        let mut best_magnitude = rows[column][column].abs();
        for (candidate, row) in rows.iter().enumerate().skip(column + 1) {
            let magnitude = row[column].abs();
            if magnitude > best_magnitude {
                best_magnitude = magnitude;
                pivot_row = candidate;
            }
        }
        if rows[pivot_row][column] == 0.0 {
            return Err(singular_transform("Affine3"));
        }
        rows.swap(column, pivot_row);
        let pivot = rows[column][column];
        for value in &mut rows[column] {
            *value /= pivot;
        }
        if !finite(&rows[column]) {
            return Err(non_finite_arithmetic("Affine3 inversion"));
        }
        let normalized_pivot = rows[column];
        for (row_index, row) in rows.iter_mut().enumerate() {
            if row_index == column {
                continue;
            }
            let factor = row[column];
            for index in 0..6 {
                row[index] -= factor * normalized_pivot[index];
            }
            if !finite(row) {
                return Err(non_finite_arithmetic("Affine3 inversion"));
            }
        }
    }
    Ok([
        [rows[0][3], rows[0][4], rows[0][5]],
        [rows[1][3], rows[1][4], rows[1][5]],
        [rows[2][3], rows[2][4], rows[2][5]],
    ])
}

fn invert_linear2_by_columns(
    linear: [[f64; 2]; 2],
    scales: [f64; 2],
) -> Result<[[f64; 2]; 2], PortablePlotError> {
    if scales.contains(&0.0) {
        return Err(singular_transform("Affine2"));
    }
    let rows = [
        [linear[0][0] / scales[0], linear[0][1] / scales[1], 1.0, 0.0],
        [linear[1][0] / scales[0], linear[1][1] / scales[1], 0.0, 1.0],
    ];
    let equilibrated_inverse = gauss_jordan2(rows)?;
    let inverse = [
        [
            equilibrated_inverse[0][0] / scales[0],
            equilibrated_inverse[0][1] / scales[0],
        ],
        [
            equilibrated_inverse[1][0] / scales[1],
            equilibrated_inverse[1][1] / scales[1],
        ],
    ];
    if !inverse.iter().flatten().all(|value| value.is_finite()) {
        return Err(non_finite_arithmetic("Affine2 inversion"));
    }
    Ok(inverse)
}

fn invert_linear2_by_rows(
    linear: [[f64; 2]; 2],
    scales: [f64; 2],
) -> Result<[[f64; 2]; 2], PortablePlotError> {
    if scales.contains(&0.0) {
        return Err(singular_transform("Affine2"));
    }
    let rows = [
        [linear[0][0] / scales[0], linear[0][1] / scales[0], 1.0, 0.0],
        [linear[1][0] / scales[1], linear[1][1] / scales[1], 0.0, 1.0],
    ];
    let equilibrated_inverse = gauss_jordan2(rows)?;
    let inverse = [
        [
            equilibrated_inverse[0][0] / scales[0],
            equilibrated_inverse[0][1] / scales[1],
        ],
        [
            equilibrated_inverse[1][0] / scales[0],
            equilibrated_inverse[1][1] / scales[1],
        ],
    ];
    if !inverse.iter().flatten().all(|value| value.is_finite()) {
        return Err(non_finite_arithmetic("Affine2 inversion"));
    }
    Ok(inverse)
}

fn invert_linear2(linear: [[f64; 2]; 2]) -> Result<[[f64; 2]; 2], PortablePlotError> {
    if source_proves_singular2(linear) {
        return Err(singular_transform("Affine2"));
    }
    let column_scales = [
        linear[0][0].abs().max(linear[1][0].abs()),
        linear[0][1].abs().max(linear[1][1].abs()),
    ];
    let row_scales = [
        linear[0][0].abs().max(linear[0][1].abs()),
        linear[1][0].abs().max(linear[1][1].abs()),
    ];
    let column_scaling_lost_nonzero = linear.iter().any(|values| {
        values.iter().enumerate().any(|(column, value)| {
            *value != 0.0 && column_scales[column] != 0.0 && *value / column_scales[column] == 0.0
        })
    });
    let row_scaling_lost_nonzero = linear.iter().enumerate().any(|(row, values)| {
        values
            .iter()
            .any(|value| *value != 0.0 && row_scales[row] != 0.0 && *value / row_scales[row] == 0.0)
    });

    let column_result = invert_linear2_by_columns(linear, column_scales);
    if !column_scaling_lost_nonzero {
        if let Ok(inverse) = column_result {
            if inverse_is_certified2(linear, inverse) {
                return Ok(inverse);
            }
        }
    }
    let row_result = invert_linear2_by_rows(linear, row_scales);
    if !row_scaling_lost_nonzero {
        if let Ok(inverse) = row_result {
            if inverse_is_certified2(linear, inverse) {
                return Ok(inverse);
            }
        }
    }
    Err(non_finite_arithmetic("Affine2 inversion"))
}

fn invert_linear3_by_columns(
    linear: [[f64; 3]; 3],
    scales: [f64; 3],
) -> Result<[[f64; 3]; 3], PortablePlotError> {
    if scales.contains(&0.0) {
        return Err(singular_transform("Affine3"));
    }
    let rows = [
        [
            linear[0][0] / scales[0],
            linear[0][1] / scales[1],
            linear[0][2] / scales[2],
            1.0,
            0.0,
            0.0,
        ],
        [
            linear[1][0] / scales[0],
            linear[1][1] / scales[1],
            linear[1][2] / scales[2],
            0.0,
            1.0,
            0.0,
        ],
        [
            linear[2][0] / scales[0],
            linear[2][1] / scales[1],
            linear[2][2] / scales[2],
            0.0,
            0.0,
            1.0,
        ],
    ];
    let equilibrated_inverse = gauss_jordan3(rows)?;
    let inverse = [
        [
            equilibrated_inverse[0][0] / scales[0],
            equilibrated_inverse[0][1] / scales[0],
            equilibrated_inverse[0][2] / scales[0],
        ],
        [
            equilibrated_inverse[1][0] / scales[1],
            equilibrated_inverse[1][1] / scales[1],
            equilibrated_inverse[1][2] / scales[1],
        ],
        [
            equilibrated_inverse[2][0] / scales[2],
            equilibrated_inverse[2][1] / scales[2],
            equilibrated_inverse[2][2] / scales[2],
        ],
    ];
    if !inverse.iter().flatten().all(|value| value.is_finite()) {
        return Err(non_finite_arithmetic("Affine3 inversion"));
    }
    Ok(inverse)
}

fn invert_linear3_by_rows(
    linear: [[f64; 3]; 3],
    scales: [f64; 3],
) -> Result<[[f64; 3]; 3], PortablePlotError> {
    if scales.contains(&0.0) {
        return Err(singular_transform("Affine3"));
    }
    let rows = [
        [
            linear[0][0] / scales[0],
            linear[0][1] / scales[0],
            linear[0][2] / scales[0],
            1.0,
            0.0,
            0.0,
        ],
        [
            linear[1][0] / scales[1],
            linear[1][1] / scales[1],
            linear[1][2] / scales[1],
            0.0,
            1.0,
            0.0,
        ],
        [
            linear[2][0] / scales[2],
            linear[2][1] / scales[2],
            linear[2][2] / scales[2],
            0.0,
            0.0,
            1.0,
        ],
    ];
    let equilibrated_inverse = gauss_jordan3(rows)?;
    let inverse = [
        [
            equilibrated_inverse[0][0] / scales[0],
            equilibrated_inverse[0][1] / scales[1],
            equilibrated_inverse[0][2] / scales[2],
        ],
        [
            equilibrated_inverse[1][0] / scales[0],
            equilibrated_inverse[1][1] / scales[1],
            equilibrated_inverse[1][2] / scales[2],
        ],
        [
            equilibrated_inverse[2][0] / scales[0],
            equilibrated_inverse[2][1] / scales[1],
            equilibrated_inverse[2][2] / scales[2],
        ],
    ];
    if !inverse.iter().flatten().all(|value| value.is_finite()) {
        return Err(non_finite_arithmetic("Affine3 inversion"));
    }
    Ok(inverse)
}

fn invert_linear3(linear: [[f64; 3]; 3]) -> Result<[[f64; 3]; 3], PortablePlotError> {
    if source_proves_singular3(linear) {
        return Err(singular_transform("Affine3"));
    }
    let column_scales = [
        linear[0][0]
            .abs()
            .max(linear[1][0].abs())
            .max(linear[2][0].abs()),
        linear[0][1]
            .abs()
            .max(linear[1][1].abs())
            .max(linear[2][1].abs()),
        linear[0][2]
            .abs()
            .max(linear[1][2].abs())
            .max(linear[2][2].abs()),
    ];
    let row_scales = [
        linear[0][0]
            .abs()
            .max(linear[0][1].abs())
            .max(linear[0][2].abs()),
        linear[1][0]
            .abs()
            .max(linear[1][1].abs())
            .max(linear[1][2].abs()),
        linear[2][0]
            .abs()
            .max(linear[2][1].abs())
            .max(linear[2][2].abs()),
    ];
    let column_scaling_lost_nonzero = linear.iter().any(|values| {
        values.iter().enumerate().any(|(column, value)| {
            *value != 0.0 && column_scales[column] != 0.0 && *value / column_scales[column] == 0.0
        })
    });
    let row_scaling_lost_nonzero = linear.iter().enumerate().any(|(row, values)| {
        values
            .iter()
            .any(|value| *value != 0.0 && row_scales[row] != 0.0 && *value / row_scales[row] == 0.0)
    });

    let column_result = invert_linear3_by_columns(linear, column_scales);
    if !column_scaling_lost_nonzero {
        if let Ok(inverse) = column_result {
            if inverse_is_certified3(linear, inverse) {
                return Ok(inverse);
            }
        }
    }
    let row_result = invert_linear3_by_rows(linear, row_scales);
    if !row_scaling_lost_nonzero {
        if let Ok(inverse) = row_result {
            if inverse_is_certified3(linear, inverse) {
                return Ok(inverse);
            }
        }
    }
    Err(non_finite_arithmetic("Affine3 inversion"))
}

/// Finite two-dimensional point.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point2 {
    x: f64,
    y: f64,
}

impl Point2 {
    pub fn new(x: f64, y: f64) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y]) {
            return Err(non_finite_input("Point2"));
        }
        Ok(Self { x, y })
    }

    fn from_arithmetic(x: f64, y: f64, operation: &str) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y]) {
            return Err(non_finite_arithmetic(operation));
        }
        Ok(Self { x, y })
    }

    pub fn x(self) -> f64 {
        self.x
    }

    pub fn y(self) -> f64 {
        self.y
    }
}

/// Finite two-dimensional direction or offset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vector2 {
    x: f64,
    y: f64,
}

impl Vector2 {
    pub fn new(x: f64, y: f64) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y]) {
            return Err(non_finite_input("Vector2"));
        }
        Ok(Self { x, y })
    }

    fn from_arithmetic(x: f64, y: f64, operation: &str) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y]) {
            return Err(non_finite_arithmetic(operation));
        }
        Ok(Self { x, y })
    }

    pub fn x(self) -> f64 {
        self.x
    }

    pub fn y(self) -> f64 {
        self.y
    }
}

/// Finite three-dimensional point.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point3 {
    x: f64,
    y: f64,
    z: f64,
}

impl Point3 {
    pub fn new(x: f64, y: f64, z: f64) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y, z]) {
            return Err(non_finite_input("Point3"));
        }
        Ok(Self { x, y, z })
    }

    fn from_arithmetic(x: f64, y: f64, z: f64, operation: &str) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y, z]) {
            return Err(non_finite_arithmetic(operation));
        }
        Ok(Self { x, y, z })
    }

    fn as_vector(self) -> Vector3 {
        Vector3 {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    pub fn x(self) -> f64 {
        self.x
    }

    pub fn y(self) -> f64 {
        self.y
    }

    pub fn z(self) -> f64 {
        self.z
    }
}

/// Finite three-dimensional direction or offset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vector3 {
    x: f64,
    y: f64,
    z: f64,
}

impl Vector3 {
    pub fn new(x: f64, y: f64, z: f64) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y, z]) {
            return Err(non_finite_input("Vector3"));
        }
        Ok(Self { x, y, z })
    }

    fn from_arithmetic(x: f64, y: f64, z: f64, operation: &str) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y, z]) {
            return Err(non_finite_arithmetic(operation));
        }
        Ok(Self { x, y, z })
    }

    fn normalized_for_ocs(self) -> Result<Self, PortablePlotError> {
        let scale = self.x.abs().max(self.y.abs()).max(self.z.abs());
        if scale == 0.0 {
            return Err(PortablePlotError::new(
                "zero_normal",
                "OCS normal must have non-zero length",
            ));
        }
        let scaled_x = self.x / scale;
        let scaled_y = self.y / scale;
        let scaled_z = self.z / scale;
        let scaled_length =
            (scaled_x * scaled_x + scaled_y * scaled_y + scaled_z * scaled_z).sqrt();
        Self::from_arithmetic(
            scaled_x / scaled_length,
            scaled_y / scaled_length,
            scaled_z / scaled_length,
            "OCS normal normalization",
        )
    }

    fn cross(self, other: Self, operation: &str) -> Result<Self, PortablePlotError> {
        Self::from_arithmetic(
            self.y * other.z - self.z * other.y,
            self.z * other.x - self.x * other.z,
            self.x * other.y - self.y * other.x,
            operation,
        )
    }

    fn normalized_axis(self, operation: &str) -> Result<Self, PortablePlotError> {
        let scale = self.x.abs().max(self.y.abs()).max(self.z.abs());
        if scale == 0.0 {
            return Err(PortablePlotError::new(
                "zero_normal",
                "arbitrary-axis construction produced a zero direction",
            ));
        }
        let x = self.x / scale;
        let y = self.y / scale;
        let z = self.z / scale;
        let length = (x * x + y * y + z * z).sqrt();
        Self::from_arithmetic(x / length, y / length, z / length, operation)
    }

    pub fn x(self) -> f64 {
        self.x
    }

    pub fn y(self) -> f64 {
        self.y
    }

    pub fn z(self) -> f64 {
        self.z
    }
}

/// Checked two-dimensional affine transform.
///
/// `first.then(second)` applies `first` and then `second`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Affine2 {
    m11: f64,
    m12: f64,
    m21: f64,
    m22: f64,
    tx: f64,
    ty: f64,
}

impl Affine2 {
    pub fn identity() -> Self {
        Self {
            m11: 1.0,
            m12: 0.0,
            m21: 0.0,
            m22: 1.0,
            tx: 0.0,
            ty: 0.0,
        }
    }

    pub fn translation(offset: Vector2) -> Self {
        Self {
            tx: offset.x,
            ty: offset.y,
            ..Self::identity()
        }
    }

    pub fn scale(x: f64, y: f64) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y]) {
            return Err(non_finite_input("Affine2 scale"));
        }
        Ok(Self {
            m11: x,
            m12: 0.0,
            m21: 0.0,
            m22: y,
            tx: 0.0,
            ty: 0.0,
        })
    }

    pub fn rotation(angle_radians: f64) -> Result<Self, PortablePlotError> {
        if !angle_radians.is_finite() {
            return Err(non_finite_input("Affine2 rotation"));
        }
        let cosine = angle_radians.cos();
        let sine = angle_radians.sin();
        Ok(Self {
            m11: cosine,
            m12: -sine,
            m21: sine,
            m22: cosine,
            tx: 0.0,
            ty: 0.0,
        })
    }

    /// Construct a checked affine matrix in column-vector order.
    pub fn from_components(
        m11: f64,
        m12: f64,
        m21: f64,
        m22: f64,
        tx: f64,
        ty: f64,
    ) -> Result<Self, PortablePlotError> {
        Self::from_arithmetic([m11, m12, m21, m22, tx, ty], "Affine2 construction")
    }

    /// Return `[m11, m12, m21, m22, tx, ty]`.
    pub const fn components(self) -> [f64; 6] {
        [self.m11, self.m12, self.m21, self.m22, self.tx, self.ty]
    }

    fn from_arithmetic(values: [f64; 6], operation: &str) -> Result<Self, PortablePlotError> {
        if !finite(&values) {
            return Err(non_finite_arithmetic(operation));
        }
        Ok(Self {
            m11: values[0],
            m12: values[1],
            m21: values[2],
            m22: values[3],
            tx: values[4],
            ty: values[5],
        })
    }

    /// Compose transforms in application order.
    ///
    /// The returned transform is `second * self` for column-vector notation.
    pub fn then(self, second: Self) -> Result<Self, PortablePlotError> {
        Self::from_arithmetic(
            [
                second.m11 * self.m11 + second.m12 * self.m21,
                second.m11 * self.m12 + second.m12 * self.m22,
                second.m21 * self.m11 + second.m22 * self.m21,
                second.m21 * self.m12 + second.m22 * self.m22,
                second.m11 * self.tx + second.m12 * self.ty + second.tx,
                second.m21 * self.tx + second.m22 * self.ty + second.ty,
            ],
            "Affine2 composition",
        )
    }

    pub fn transform_point(self, point: Point2) -> Result<Point2, PortablePlotError> {
        Point2::from_arithmetic(
            self.m11 * point.x + self.m12 * point.y + self.tx,
            self.m21 * point.x + self.m22 * point.y + self.ty,
            "Affine2 point transformation",
        )
    }

    pub fn transform_vector(self, vector: Vector2) -> Result<Vector2, PortablePlotError> {
        Vector2::from_arithmetic(
            self.m11 * vector.x + self.m12 * vector.y,
            self.m21 * vector.x + self.m22 * vector.y,
            "Affine2 vector transformation",
        )
    }

    pub fn determinant(self) -> Result<f64, PortablePlotError> {
        let determinant = self.m11 * self.m22 - self.m12 * self.m21;
        if !determinant.is_finite() {
            return Err(non_finite_arithmetic("Affine2 determinant"));
        }
        Ok(determinant)
    }

    pub fn inverse(self) -> Result<Self, PortablePlotError> {
        let inverse = invert_linear2([[self.m11, self.m12], [self.m21, self.m22]])?;
        Self::from_arithmetic(
            [
                inverse[0][0],
                inverse[0][1],
                inverse[1][0],
                inverse[1][1],
                -(inverse[0][0] * self.tx + inverse[0][1] * self.ty),
                -(inverse[1][0] * self.tx + inverse[1][1] * self.ty),
            ],
            "Affine2 inversion",
        )
    }
}

/// Checked three-dimensional affine transform.
///
/// `first.then(second)` applies `first` and then `second`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Affine3 {
    linear: [[f64; 3]; 3],
    translation: [f64; 3],
}

impl Affine3 {
    pub fn identity() -> Self {
        Self {
            linear: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
            translation: [0.0; 3],
        }
    }

    pub fn translation(offset: Vector3) -> Self {
        Self {
            translation: [offset.x, offset.y, offset.z],
            ..Self::identity()
        }
    }

    pub fn scale(x: f64, y: f64, z: f64) -> Result<Self, PortablePlotError> {
        if !finite(&[x, y, z]) {
            return Err(non_finite_input("Affine3 scale"));
        }
        Ok(Self {
            linear: [[x, 0.0, 0.0], [0.0, y, 0.0], [0.0, 0.0, z]],
            translation: [0.0; 3],
        })
    }

    pub fn rotation_z(angle_radians: f64) -> Result<Self, PortablePlotError> {
        if !angle_radians.is_finite() {
            return Err(non_finite_input("Affine3 rotation"));
        }
        let cosine = angle_radians.cos();
        let sine = angle_radians.sin();
        Ok(Self {
            linear: [[cosine, -sine, 0.0], [sine, cosine, 0.0], [0.0, 0.0, 1.0]],
            translation: [0.0; 3],
        })
    }

    fn from_basis(x_axis: Vector3, y_axis: Vector3, z_axis: Vector3) -> Self {
        Self {
            linear: [
                [x_axis.x, y_axis.x, z_axis.x],
                [x_axis.y, y_axis.y, z_axis.y],
                [x_axis.z, y_axis.z, z_axis.z],
            ],
            translation: [0.0; 3],
        }
    }

    fn from_arithmetic(
        linear: [[f64; 3]; 3],
        translation: [f64; 3],
        operation: &str,
    ) -> Result<Self, PortablePlotError> {
        if !linear.iter().flatten().all(|value| value.is_finite()) || !finite(&translation) {
            return Err(non_finite_arithmetic(operation));
        }
        Ok(Self {
            linear,
            translation,
        })
    }

    /// Compose transforms in application order.
    ///
    /// The returned transform is `second * self` for column-vector notation.
    pub fn then(self, second: Self) -> Result<Self, PortablePlotError> {
        let mut linear = [[0.0; 3]; 3];
        for (row, output_row) in linear.iter_mut().enumerate() {
            for (column, output) in output_row.iter_mut().enumerate() {
                *output = second.linear[row][0] * self.linear[0][column]
                    + second.linear[row][1] * self.linear[1][column]
                    + second.linear[row][2] * self.linear[2][column];
            }
        }
        let translation = [
            second.linear[0][0] * self.translation[0]
                + second.linear[0][1] * self.translation[1]
                + second.linear[0][2] * self.translation[2]
                + second.translation[0],
            second.linear[1][0] * self.translation[0]
                + second.linear[1][1] * self.translation[1]
                + second.linear[1][2] * self.translation[2]
                + second.translation[1],
            second.linear[2][0] * self.translation[0]
                + second.linear[2][1] * self.translation[1]
                + second.linear[2][2] * self.translation[2]
                + second.translation[2],
        ];
        Self::from_arithmetic(linear, translation, "Affine3 composition")
    }

    pub fn transform_point(self, point: Point3) -> Result<Point3, PortablePlotError> {
        Point3::from_arithmetic(
            self.linear[0][0] * point.x
                + self.linear[0][1] * point.y
                + self.linear[0][2] * point.z
                + self.translation[0],
            self.linear[1][0] * point.x
                + self.linear[1][1] * point.y
                + self.linear[1][2] * point.z
                + self.translation[1],
            self.linear[2][0] * point.x
                + self.linear[2][1] * point.y
                + self.linear[2][2] * point.z
                + self.translation[2],
            "Affine3 point transformation",
        )
    }

    pub fn transform_vector(self, vector: Vector3) -> Result<Vector3, PortablePlotError> {
        Vector3::from_arithmetic(
            self.linear[0][0] * vector.x
                + self.linear[0][1] * vector.y
                + self.linear[0][2] * vector.z,
            self.linear[1][0] * vector.x
                + self.linear[1][1] * vector.y
                + self.linear[1][2] * vector.z,
            self.linear[2][0] * vector.x
                + self.linear[2][1] * vector.y
                + self.linear[2][2] * vector.z,
            "Affine3 vector transformation",
        )
    }

    pub fn determinant(self) -> Result<f64, PortablePlotError> {
        let matrix = self.linear;
        let determinant = matrix[0][0]
            * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1])
            - matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0])
            + matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]);
        if !determinant.is_finite() {
            return Err(non_finite_arithmetic("Affine3 determinant"));
        }
        Ok(determinant)
    }

    pub fn inverse(self) -> Result<Self, PortablePlotError> {
        let inverse = invert_linear3(self.linear)?;
        let translation = [
            -(inverse[0][0] * self.translation[0]
                + inverse[0][1] * self.translation[1]
                + inverse[0][2] * self.translation[2]),
            -(inverse[1][0] * self.translation[0]
                + inverse[1][1] * self.translation[1]
                + inverse[1][2] * self.translation[2]),
            -(inverse[2][0] * self.translation[0]
                + inverse[2][1] * self.translation[1]
                + inverse[2][2] * self.translation[2]),
        ];
        Self::from_arithmetic(inverse, translation, "Affine3 inversion")
    }
}

/// Right-handed OCS basis generated from an extrusion normal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OcsFrame {
    x_axis: Vector3,
    y_axis: Vector3,
    normal: Vector3,
}

impl OcsFrame {
    /// Construct the exact arbitrary-axis frame documented for DXF.
    pub fn from_normal(normal: Vector3) -> Result<Self, PortablePlotError> {
        let normal = normal.normalized_for_ocs()?;
        let world_y = Vector3 {
            x: 0.0,
            y: 1.0,
            z: 0.0,
        };
        let world_z = Vector3 {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        };
        let x_axis = if normal.x.abs() < ARBITRARY_AXIS_THRESHOLD
            && normal.y.abs() < ARBITRARY_AXIS_THRESHOLD
        {
            world_y.cross(normal, "OCS world-Y cross normal")?
        } else {
            world_z.cross(normal, "OCS world-Z cross normal")?
        }
        .normalized_axis("OCS X-axis normalization")?;
        let y_axis = normal
            .cross(x_axis, "OCS normal cross X axis")?
            .normalized_axis("OCS Y-axis normalization")?;
        Ok(Self {
            x_axis,
            y_axis,
            normal,
        })
    }

    pub fn x_axis(self) -> Vector3 {
        self.x_axis
    }

    pub fn y_axis(self) -> Vector3 {
        self.y_axis
    }

    pub fn normal(self) -> Vector3 {
        self.normal
    }

    pub fn as_affine3(self) -> Affine3 {
        Affine3::from_basis(self.x_axis, self.y_axis, self.normal)
    }

    pub fn point_to_wcs(self, point: Point3) -> Result<Point3, PortablePlotError> {
        self.as_affine3().transform_point(point)
    }
}

/// OCS-aware transform from block microspace to drawing WCS.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlockInsertTransform3 {
    affine: Affine3,
}

impl BlockInsertTransform3 {
    /// Construct `OCS * T(insert_ocs) * Rz * S * T(-block_base)`.
    pub fn new(
        block_base: Point3,
        insert_ocs: Point3,
        scale: Vector3,
        rotation_radians: f64,
        normal: Vector3,
    ) -> Result<Self, PortablePlotError> {
        if scale.x == 0.0 || scale.y == 0.0 || scale.z == 0.0 {
            return Err(PortablePlotError::new(
                "zero_insert_scale",
                "INSERT scale components must be non-zero",
            ));
        }
        let frame = OcsFrame::from_normal(normal)?;
        let from_block_base = Affine3::translation(Vector3 {
            x: -block_base.x,
            y: -block_base.y,
            z: -block_base.z,
        });
        let scale = Affine3::scale(scale.x, scale.y, scale.z)?;
        let rotation = Affine3::rotation_z(rotation_radians)?;
        let to_insert = Affine3::translation(insert_ocs.as_vector());
        let affine = from_block_base
            .then(scale)?
            .then(rotation)?
            .then(to_insert)?
            .then(frame.as_affine3())?;
        Ok(Self { affine })
    }

    pub fn affine(self) -> Affine3 {
        self.affine
    }

    pub fn transform_point(self, point: Point3) -> Result<Point3, PortablePlotError> {
        self.affine.transform_point(point)
    }

    pub fn transform_vector(self, vector: Vector3) -> Result<Vector3, PortablePlotError> {
        self.affine.transform_vector(vector)
    }
}

#[cfg(test)]
mod tests {
    use std::f64::consts::{FRAC_PI_2, FRAC_PI_4};

    use super::*;

    const TOLERANCE: f64 = 1.0e-11;

    fn point2(x: f64, y: f64) -> Point2 {
        Point2::new(x, y).unwrap()
    }

    fn vector2(x: f64, y: f64) -> Vector2 {
        Vector2::new(x, y).unwrap()
    }

    fn point3(x: f64, y: f64, z: f64) -> Point3 {
        Point3::new(x, y, z).unwrap()
    }

    fn vector3(x: f64, y: f64, z: f64) -> Vector3 {
        Vector3::new(x, y, z).unwrap()
    }

    fn assert_near(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= TOLERANCE,
            "expected {expected}, got {actual}"
        );
    }

    fn assert_point2(actual: Point2, expected: Point2) {
        assert_near(actual.x(), expected.x());
        assert_near(actual.y(), expected.y());
    }

    fn assert_vector2(actual: Vector2, expected: Vector2) {
        assert_near(actual.x(), expected.x());
        assert_near(actual.y(), expected.y());
    }

    fn assert_point3(actual: Point3, expected: Point3) {
        assert_near(actual.x(), expected.x());
        assert_near(actual.y(), expected.y());
        assert_near(actual.z(), expected.z());
    }

    fn assert_vector3(actual: Vector3, expected: Vector3) {
        assert_near(actual.x(), expected.x());
        assert_near(actual.y(), expected.y());
        assert_near(actual.z(), expected.z());
    }

    #[test]
    fn constructors_reject_non_finite_values() {
        for error in [
            Point2::new(f64::NAN, 0.0).unwrap_err(),
            Vector2::new(0.0, f64::INFINITY).unwrap_err(),
            Point3::new(0.0, f64::NEG_INFINITY, 0.0).unwrap_err(),
            Vector3::new(0.0, 0.0, f64::NAN).unwrap_err(),
        ] {
            assert_eq!(error.code(), "non_finite_input");
        }
    }

    #[test]
    fn affine2_identity_translation_and_point_vector_distinction() {
        let translation = Affine2::translation(vector2(3.0, -4.0));
        assert_point2(
            Affine2::identity()
                .transform_point(point2(1.0, 2.0))
                .unwrap(),
            point2(1.0, 2.0),
        );
        assert_point2(
            translation.transform_point(point2(1.0, 2.0)).unwrap(),
            point2(4.0, -2.0),
        );
        assert_vector2(
            translation.transform_vector(vector2(1.0, 2.0)).unwrap(),
            vector2(1.0, 2.0),
        );
    }

    #[test]
    fn affine2_composition_order_is_application_order() {
        let translate = Affine2::translation(vector2(2.0, 0.0));
        let rotate = Affine2::rotation(FRAC_PI_2).unwrap();
        let translated_then_rotated = translate.then(rotate).unwrap();
        let rotated_then_translated = rotate.then(translate).unwrap();
        assert_point2(
            translated_then_rotated
                .transform_point(point2(1.0, 0.0))
                .unwrap(),
            point2(0.0, 3.0),
        );
        assert_point2(
            rotated_then_translated
                .transform_point(point2(1.0, 0.0))
                .unwrap(),
            point2(2.0, 1.0),
        );
    }

    #[test]
    fn affine2_nonuniform_scale_rotation_and_inverse_round_trip() {
        let transform = Affine2::scale(2.0, 3.0)
            .unwrap()
            .then(Affine2::rotation(FRAC_PI_4).unwrap())
            .unwrap()
            .then(Affine2::translation(vector2(5.0, -7.0)))
            .unwrap();
        let source = point2(4.0, -2.0);
        let transformed = transform.transform_point(source).unwrap();
        assert_point2(
            transform
                .inverse()
                .unwrap()
                .transform_point(transformed)
                .unwrap(),
            source,
        );
    }

    #[test]
    fn affine2_singular_and_non_finite_arithmetic_reject() {
        assert_eq!(
            Affine2::scale(0.0, 1.0)
                .unwrap()
                .inverse()
                .unwrap_err()
                .code(),
            "singular_transform"
        );
        assert_eq!(
            Affine2::scale(f64::MAX, 1.0)
                .unwrap()
                .then(Affine2::scale(2.0, 1.0).unwrap())
                .unwrap_err()
                .code(),
            "non_finite_arithmetic"
        );
        assert_eq!(
            Affine2::scale(f64::MAX, 1.0)
                .unwrap()
                .transform_point(point2(2.0, 0.0))
                .unwrap_err()
                .code(),
            "non_finite_arithmetic"
        );
        assert_eq!(
            Affine2::scale(f64::from_bits(1), 1.0)
                .unwrap()
                .inverse()
                .unwrap_err()
                .code(),
            "non_finite_arithmetic"
        );
    }

    #[test]
    fn affine2_inverse_survives_determinant_underflow() {
        let inverse = Affine2::scale(1.0e-200, 1.0e-200)
            .unwrap()
            .inverse()
            .unwrap();
        let transformed = inverse.transform_vector(vector2(1.0, 1.0)).unwrap();
        assert_eq!(transformed.x(), 1.0e200);
        assert_eq!(transformed.y(), 1.0e200);
    }

    #[test]
    fn affine2_inverse_survives_pivot_ratio_underflow() {
        let high = f64::MAX / 4.0;
        let epsilon = 1.0e-16;
        let inverse = Affine2 {
            m11: 0.0,
            m12: high,
            m21: epsilon,
            m22: high,
            tx: 0.0,
            ty: 0.0,
        }
        .inverse()
        .unwrap();

        let first_column = inverse.transform_vector(vector2(1.0, 0.0)).unwrap();
        assert_near(first_column.x() * epsilon, -1.0);
        assert_near(first_column.y() * high, 1.0);
        let second_column = inverse.transform_vector(vector2(0.0, 1.0)).unwrap();
        assert_near(second_column.x() * epsilon, 1.0);
        assert_eq!(second_column.y(), 0.0);
    }

    #[test]
    fn affine2_inverse_survives_transposed_pivot_ratio_underflow() {
        let high = f64::MAX / 4.0;
        let epsilon = 1.0e-16;
        let inverse = Affine2 {
            m11: 0.0,
            m12: epsilon,
            m21: high,
            m22: high,
            tx: 0.0,
            ty: 0.0,
        }
        .inverse()
        .unwrap();

        let first_column = inverse.transform_vector(vector2(1.0, 0.0)).unwrap();
        assert_near(first_column.x() * epsilon, -1.0);
        assert_near(first_column.y() * epsilon, 1.0);
        let second_column = inverse.transform_vector(vector2(0.0, 1.0)).unwrap();
        assert_near(second_column.x() * high, 1.0);
        assert_eq!(second_column.y(), 0.0);
    }

    #[test]
    fn affine2_rounded_rank_ambiguity_is_not_classified_as_singular() {
        let a = f64::from_bits(0x3feffffffffffff4);
        let b = f64::from_bits(0x3feffffffffffff5);
        let d = f64::from_bits(0x3feffffffffffff6);
        let error = Affine2 {
            m11: a,
            m12: b,
            m21: b,
            m22: d,
            tx: 0.0,
            ty: 0.0,
        }
        .inverse()
        .unwrap_err();

        assert_eq!(error.code(), "non_finite_arithmetic");
    }

    #[test]
    fn affine2_nontrivial_singular_source_rejects_conservatively() {
        let error = Affine2 {
            m11: 1.0,
            m12: 2.0,
            m21: 2.0,
            m22: 4.0,
            tx: 0.0,
            ty: 0.0,
        }
        .inverse()
        .unwrap_err();

        assert_eq!(error.code(), "non_finite_arithmetic");
    }

    #[test]
    fn affine3_point_vector_and_inverse_round_trip() {
        let transform = Affine3::scale(2.0, -3.0, 4.0)
            .unwrap()
            .then(Affine3::rotation_z(FRAC_PI_4).unwrap())
            .unwrap()
            .then(Affine3::translation(vector3(5.0, 6.0, 7.0)))
            .unwrap();
        let source = point3(1.0, 2.0, 3.0);
        let transformed = transform.transform_point(source).unwrap();
        assert_point3(
            transform
                .inverse()
                .unwrap()
                .transform_point(transformed)
                .unwrap(),
            source,
        );
        assert_vector3(
            Affine3::translation(vector3(5.0, 6.0, 7.0))
                .transform_vector(vector3(1.0, 2.0, 3.0))
                .unwrap(),
            vector3(1.0, 2.0, 3.0),
        );
    }

    #[test]
    fn affine3_arithmetic_overflow_rejects() {
        assert_eq!(
            Affine3::scale(f64::MAX, 1.0, 1.0)
                .unwrap()
                .then(Affine3::scale(2.0, 1.0, 1.0).unwrap())
                .unwrap_err()
                .code(),
            "non_finite_arithmetic"
        );
        assert_eq!(
            Affine3::scale(f64::MAX, 1.0, 1.0)
                .unwrap()
                .transform_vector(vector3(2.0, 0.0, 0.0))
                .unwrap_err()
                .code(),
            "non_finite_arithmetic"
        );
        assert_eq!(
            Affine3::scale(f64::from_bits(1), 1.0, 1.0)
                .unwrap()
                .inverse()
                .unwrap_err()
                .code(),
            "non_finite_arithmetic"
        );
    }

    #[test]
    fn affine3_inverse_survives_determinant_underflow() {
        let inverse = Affine3::scale(1.0e-150, 1.0e-150, 1.0e-150)
            .unwrap()
            .inverse()
            .unwrap();
        let transformed = inverse.transform_vector(vector3(1.0, 1.0, 1.0)).unwrap();
        assert_eq!(transformed.x(), 1.0e150);
        assert_eq!(transformed.y(), 1.0e150);
        assert_eq!(transformed.z(), 1.0e150);
    }

    #[test]
    fn affine3_inverse_survives_embedded_pivot_ratio_underflow() {
        let high = f64::MAX / 4.0;
        let epsilon = 1.0e-16;
        let inverse = Affine3 {
            linear: [[0.0, high, 0.0], [epsilon, high, 0.0], [0.0, 0.0, 1.0]],
            translation: [0.0; 3],
        }
        .inverse()
        .unwrap();

        let first_column = inverse.transform_vector(vector3(1.0, 0.0, 0.0)).unwrap();
        assert_near(first_column.x() * epsilon, -1.0);
        assert_near(first_column.y() * high, 1.0);
        assert_eq!(first_column.z(), 0.0);
        let second_column = inverse.transform_vector(vector3(0.0, 1.0, 0.0)).unwrap();
        assert_near(second_column.x() * epsilon, 1.0);
        assert_eq!(second_column.y(), 0.0);
        assert_eq!(second_column.z(), 0.0);
        assert_vector3(
            inverse.transform_vector(vector3(0.0, 0.0, 1.0)).unwrap(),
            vector3(0.0, 0.0, 1.0),
        );
    }

    #[test]
    fn affine3_inverse_survives_embedded_transposed_pivot_ratio_underflow() {
        let high = f64::MAX / 4.0;
        let epsilon = 1.0e-16;
        let inverse = Affine3 {
            linear: [[0.0, epsilon, 0.0], [high, high, 0.0], [0.0, 0.0, 1.0]],
            translation: [0.0; 3],
        }
        .inverse()
        .unwrap();

        let first_column = inverse.transform_vector(vector3(1.0, 0.0, 0.0)).unwrap();
        assert_near(first_column.x() * epsilon, -1.0);
        assert_near(first_column.y() * epsilon, 1.0);
        assert_eq!(first_column.z(), 0.0);
        let second_column = inverse.transform_vector(vector3(0.0, 1.0, 0.0)).unwrap();
        assert_near(second_column.x() * high, 1.0);
        assert_eq!(second_column.y(), 0.0);
        assert_eq!(second_column.z(), 0.0);
        assert_vector3(
            inverse.transform_vector(vector3(0.0, 0.0, 1.0)).unwrap(),
            vector3(0.0, 0.0, 1.0),
        );
    }

    #[test]
    fn affine3_rounded_rank_ambiguity_is_not_classified_as_singular() {
        let a = f64::from_bits(0x3feffffffffffff4);
        let b = f64::from_bits(0x3feffffffffffff5);
        let d = f64::from_bits(0x3feffffffffffff6);
        let error = Affine3 {
            linear: [[a, b, 0.0], [b, d, 0.0], [0.0, 0.0, 1.0]],
            translation: [0.0; 3],
        }
        .inverse()
        .unwrap_err();

        assert_eq!(error.code(), "non_finite_arithmetic");
    }

    #[test]
    fn affine3_rejects_uncertified_inverse_of_exact_singular_source() {
        let error = Affine3 {
            linear: [[-2.0, -1.0, -3.0], [0.0, 3.0, 1.0], [-2.0, 2.0, -2.0]],
            translation: [0.0; 3],
        }
        .inverse()
        .unwrap_err();

        assert_eq!(error.code(), "non_finite_arithmetic");
    }

    #[test]
    fn affine3_rejects_cancellation_forged_identity_for_singular_source() {
        let error = Affine3 {
            linear: [[-2.0, -1.0, -4.0], [0.0, 1.0, 3.0], [2.0, 2.0, 7.0]],
            translation: [0.0; 3],
        }
        .inverse()
        .unwrap_err();

        assert_eq!(error.code(), "non_finite_arithmetic");
    }

    #[test]
    fn top_and_negative_z_normals_produce_right_handed_frames() {
        let top = OcsFrame::from_normal(vector3(0.0, 0.0, 1.0)).unwrap();
        assert_vector3(top.x_axis(), vector3(1.0, 0.0, 0.0));
        assert_vector3(top.y_axis(), vector3(0.0, 1.0, 0.0));
        assert_vector3(top.normal(), vector3(0.0, 0.0, 1.0));

        let negative = OcsFrame::from_normal(vector3(0.0, 0.0, -1.0)).unwrap();
        assert_vector3(negative.x_axis(), vector3(-1.0, 0.0, 0.0));
        assert_vector3(negative.y_axis(), vector3(0.0, 1.0, 0.0));
        assert_vector3(negative.normal(), vector3(0.0, 0.0, -1.0));
    }

    #[test]
    fn arbitrary_axis_threshold_is_strict() {
        let below_x = ARBITRARY_AXIS_THRESHOLD / 2.0;
        let below =
            OcsFrame::from_normal(vector3(below_x, 0.0, (1.0 - below_x * below_x).sqrt())).unwrap();
        assert!(below.x_axis().x() > 0.99);

        let at_x = ARBITRARY_AXIS_THRESHOLD;
        let at = OcsFrame::from_normal(vector3(at_x, 0.0, (1.0 - at_x * at_x).sqrt())).unwrap();
        assert_vector3(at.x_axis(), vector3(0.0, 1.0, 0.0));

        let above_x = ARBITRARY_AXIS_THRESHOLD * 2.0;
        let above =
            OcsFrame::from_normal(vector3(above_x, 0.0, (1.0 - above_x * above_x).sqrt())).unwrap();
        assert_vector3(above.x_axis(), vector3(0.0, 1.0, 0.0));
    }

    #[test]
    fn ocs_frames_are_scale_invariant_and_robust_for_extreme_normals() {
        let first = OcsFrame::from_normal(vector3(2.0, -3.0, 4.0)).unwrap();
        let scaled = OcsFrame::from_normal(vector3(20.0, -30.0, 40.0)).unwrap();
        assert_vector3(first.x_axis(), scaled.x_axis());
        assert_vector3(first.y_axis(), scaled.y_axis());
        assert_vector3(first.normal(), scaled.normal());

        let extreme = OcsFrame::from_normal(vector3(f64::MAX, f64::MAX, f64::MAX)).unwrap();
        let expected = 1.0 / 3.0_f64.sqrt();
        assert_vector3(extreme.normal(), vector3(expected, expected, expected));
    }

    #[test]
    fn oblique_ocs_frame_maps_points_using_orthonormal_axes() {
        let frame = OcsFrame::from_normal(vector3(1.0, 1.0, 1.0)).unwrap();
        assert_point3(
            frame.point_to_wcs(point3(1.0, 0.0, 0.0)).unwrap(),
            point3(frame.x_axis().x(), frame.x_axis().y(), frame.x_axis().z()),
        );
        let x = frame.x_axis();
        let y = frame.y_axis();
        let n = frame.normal();
        assert_near(x.x() * y.x() + x.y() * y.y() + x.z() * y.z(), 0.0);
        assert_near(x.x() * n.x() + x.y() * n.y() + x.z() * n.z(), 0.0);
        assert_near(y.x() * n.x() + y.y() * n.y() + y.z() * n.z(), 0.0);
    }

    #[test]
    fn zero_and_non_finite_ocs_normals_reject() {
        assert_eq!(
            OcsFrame::from_normal(vector3(0.0, 0.0, 0.0))
                .unwrap_err()
                .code(),
            "zero_normal"
        );
        assert_eq!(
            Vector3::new(f64::NAN, 0.0, 1.0).unwrap_err().code(),
            "non_finite_input"
        );
    }

    #[test]
    fn block_base_maps_to_ocs_insertion_in_wcs() {
        let base = point3(2.0, 3.0, 4.0);
        let insertion = point3(10.0, 20.0, 30.0);
        let normal = vector3(1.0, 1.0, 1.0);
        let transform =
            BlockInsertTransform3::new(base, insertion, vector3(2.0, 3.0, 4.0), FRAC_PI_4, normal)
                .unwrap();
        let expected = OcsFrame::from_normal(normal)
            .unwrap()
            .point_to_wcs(insertion)
            .unwrap();
        assert_point3(transform.transform_point(base).unwrap(), expected);
    }

    #[test]
    fn oblique_block_insert_combines_base_scale_rotation_and_insertion() {
        let transform = BlockInsertTransform3::new(
            point3(1.0, 2.0, 3.0),
            point3(10.0, 20.0, 30.0),
            vector3(2.0, 3.0, 4.0),
            FRAC_PI_2,
            vector3(1.0, 1.0, 1.0),
        )
        .unwrap();

        // Local (2,4,6) becomes (1,2,3) after base compensation,
        // (2,6,12) after scale, (-6,2,12) after rotation, and
        // (4,22,42) after OCS insertion. For N=(1,1,1), the arbitrary
        // axes are Ax=(-1,1,0)/sqrt(2) and Ay=(-1,-1,2)/sqrt(6).
        let root_two = 2.0_f64.sqrt();
        let root_three = 3.0_f64.sqrt();
        let root_six = 6.0_f64.sqrt();
        let expected = point3(
            -4.0 / root_two - 22.0 / root_six + 42.0 / root_three,
            4.0 / root_two - 22.0 / root_six + 42.0 / root_three,
            44.0 / root_six + 42.0 / root_three,
        );
        assert_point3(
            transform.transform_point(point3(2.0, 4.0, 6.0)).unwrap(),
            expected,
        );
    }

    #[test]
    fn block_insert_preserves_reflection_and_tiny_nonzero_scale() {
        let reflected = BlockInsertTransform3::new(
            point3(0.0, 0.0, 0.0),
            point3(0.0, 0.0, 0.0),
            vector3(-2.0, 3.0, 4.0),
            0.0,
            vector3(0.0, 0.0, 1.0),
        )
        .unwrap();
        assert_point3(
            reflected.transform_point(point3(1.0, 1.0, 1.0)).unwrap(),
            point3(-2.0, 3.0, 4.0),
        );

        let tiny = f64::from_bits(1);
        let tiny_transform = BlockInsertTransform3::new(
            point3(0.0, 0.0, 0.0),
            point3(0.0, 0.0, 0.0),
            vector3(tiny, 1.0, 1.0),
            0.0,
            vector3(0.0, 0.0, 1.0),
        )
        .unwrap();
        let transformed = tiny_transform
            .transform_vector(vector3(1.0, 0.0, 0.0))
            .unwrap();
        assert_eq!(transformed.x().to_bits(), tiny.to_bits());
    }

    #[test]
    fn block_insert_rejects_exact_zero_scale() {
        let error = BlockInsertTransform3::new(
            point3(0.0, 0.0, 0.0),
            point3(0.0, 0.0, 0.0),
            vector3(1.0, 0.0, 1.0),
            0.0,
            vector3(0.0, 0.0, 1.0),
        )
        .unwrap_err();
        assert_eq!(error.code(), "zero_insert_scale");
    }

    #[test]
    fn nested_noncommuting_insert_transforms_follow_application_order() {
        let inner = BlockInsertTransform3::new(
            point3(0.0, 0.0, 0.0),
            point3(1.0, 0.0, 0.0),
            vector3(1.0, 1.0, 1.0),
            FRAC_PI_2,
            vector3(0.0, 0.0, 1.0),
        )
        .unwrap();
        let outer = BlockInsertTransform3::new(
            point3(0.0, 0.0, 0.0),
            point3(0.0, 2.0, 0.0),
            vector3(2.0, 1.0, 1.0),
            0.0,
            vector3(0.0, 0.0, 1.0),
        )
        .unwrap();
        let nested = inner.affine().then(outer.affine()).unwrap();
        assert_point3(
            nested.transform_point(point3(1.0, 0.0, 0.0)).unwrap(),
            point3(2.0, 3.0, 0.0),
        );
    }
}
