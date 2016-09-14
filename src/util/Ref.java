package util;

public class Ref<T> {
  public static <T> Ref<T> wrap(T _value) { return new Ref<T>(_value); }
  public Ref(T _value) { value = _value; }
  public T value;
}
